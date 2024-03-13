<?php
 /* Copyright 2005-2017 Remit One Ltd. All rights reserved.
 Please see LICENSE.txt */ 

include_once('main.php');

import_class('dao/DAOReg.php');
import_class('business/remitter/RemitterService.php');
import_class('util/application/FlashMessages.php');
import_class('util/Comparative.php');
import_class('util/GenUtil.php');

use remitone\util\application\CSRF;
use remitone\util\FileUploadUtil;
use remitone\dao\DDCountryDAO;
use remitone\dao\ISOCountryDAO;
use remitone\dao\MemberDAO;
use remitone\dao\CustomCountryNameDAO;
use remitone\business\remitter\RemitterBaseModel;
use remitone\business\remitter\RemitterModel;
use remitone\business\agent\source\SourceAgentModel;
use remitone\business\remitter\MemberRiskScoreModel;

/**
 * Get Member
 * @param $memberID
 * @return mixed
 */
function getMember($memberID) {
	global $auth, $smarty, $base_dir, $REMITTER_VIDEO_DIR;
	
	$remitterBaseModel = RemitterBaseModel::getRemitterModel($memberID);

	if (in_array($auth->user_type(), array('Agent','Agent_Subuser','Agent_Teller'))) {
		$agentId = $auth->user_id();
		$country = $auth->country();
		$member = $remitterBaseModel->getDAO()->findByPKCheckAgent($memberID, $country, $agentId);
	} else {
		$member = $remitterBaseModel->getData();
	}
	
// Establecer el tiempo máximo de ejecución
ini_set('max_execution_time', 3000); // 300 segundos = 5 minutos

// Establecer el límite de tamaño de carga
ini_set('post_max_size', '500M'); // 50 megabytes (puedes ajustar este valor según sea necesario)

// Establecer el límite de tamaño de archivo de carga
ini_set('upload_max_filesize', '500M'); // 50 megabytes (puedes ajustar este valor según sea necesario)
	if ($member === null) {
		$smarty->assign('error', Translate::getValue('validation.remitter.insufficient_rights'));
	} else {
		$idScanClassArray = array(
			'id1_scan1' => 'id1_scan_class1',
			'id1_scan2' => 'id1_scan_class2',
			'id1_scan3' => 'id1_scan_class3',
			'id2_scan1' => 'id2_scan_class1',
			'id2_scan2' => 'id2_scan_class2',
			'id2_scan3' => 'id2_scan_class3',
			'id3_scan1' => 'id3_scan_class1',
			'id3_scan2' => 'id3_scan_class2',
			'id3_scan3' => 'id3_scan_class3',
			'id4_scan1' => 'id4_scan_class1',
			'id4_scan2' => 'id4_scan_class2',
			'id4_scan3' => 'id4_scan_class3',
			'additional_information' => 'additional_information_class',
		);
		
		foreach ($idScanClassArray as $idScanField => $idScanClass) {
			if ($member->$idScanField != '') {
				$member->$idScanClass = getTypeHTML($member->$idScanField);
			}
		}
		
		if (!empty($member->kyc_video)) {
			$member->kyc_video = json_decode($member->kyc_video);
		}
		
		if (!empty($member->kyc_video->video) && file_exists($base_dir . $REMITTER_VIDEO_DIR . $member->kyc_video->video)) {
			$member->kyc_video->kyc_video_class = getTypeHTML($member->kyc_video->video);
		} else {
			$member->kyc_video = new stdClass();
			$member->kyc_video->video = '';
			$member->kyc_video->mimetype = '';
			$member->kyc_video->kyc_video_class = '';
		}
		
		if ($member->orm_user_id!='') {
			$remitterUser = DAOReg::get("RemitterUserDAO")->findByPK($member->orm_user_id);
			$member->remitter_username = $remitterUser->username;
			$member->remitter_account_locked = $remitterUser->account_locked;
		}
	}
	
	if (!empty($member->country_of_birth) && strlen($member->country_of_birth) == 2) {
		$member->country_of_birth = DAOReg::get("ISOCountryDAO")->findByCode($member->country_of_birth)->printable_name;
	}
	
	return $member;
}

/**
 * Get File Type HTML
 * @param string $scanFile
 * @return string
 */
function getTypeHTML($scanFile) {
	$ext = FileUploadUtil::getExtension($scanFile);
	
	if(FileUploadUtil::getTypeByExtension($ext, array('image'))!==null) {
		$type = ' class="image_lightbox" data-lightbox="image-'.bin2hex(random_bytes(3)).'"';
	} else if(FileUploadUtil::getTypeByExtension($ext, array('video'))!==null) {
		$type = ' class="video_lightbox" ';
	} else {
		$type = ' target="_new" ';
	}
	return $type;
}

/**
 * Set Country Code, Store in POST
 */
function setCountryCode() {
	if (isset($_POST['country']) && !empty($_POST['country'])) {
		$country = DAOReg::get('DDCountryDAO')->findByName($_POST['country']);
		if ($country !== null) {
			$_POST['country_code'] = $country->iso_code;
		}
	}
}

/**
 * If it's an admin user type, set the remitter ID types based on the source country
 * @param ExtAuth $auth
 */
function setRemitterIDTypes($auth) {
	$adminUserTypes = array('Admin','Admin_Limited','Admin_Read','Admin_Compliance','Admin_Processing','Admin_Support','Accounts');
	$sourceCountryCode = null;

	if(in_array($auth->user_type(), $adminUserTypes) || ($auth->user_type()=='Admin_Custom' && $auth->hasPermission('edit_remitters'))){

		// Get the country code
		if ($_POST['country'] != '') {
			$countryName = $_POST['country'];
			$sourceCountryCode = DAOReg::get('DDCountryDAO')->findByName($countryName, 'source')->country_code;
		} else if ($_REQUEST['member_id'] != '' && GenUtil::isWholeNumber($_REQUEST['member_id'])) {
			$member = getMember($_REQUEST['member_id']);
			$sourceCountryCode = DAOReg::get('DDCountryDAO')->findByName($member->country, 'source')->country_code;
		}
		GenUtil::setRemitterIDs($sourceCountryCode, 'Agent'); // Pretend to be an agent (shhh!)
	}
}

/**
 * @param Smarty $smarty
 * @param $countryID
 */
function assignAgentsToSmarty($smarty, $countryID) {
	$agents = DAOReg::get('AgentDAO')->findInCountry($countryID);
	$smarty->assign('agents', $agents);
}

function getAirportsList($smarty, $countryName) {
	$country = DAOReg::get('DDCountryDAO')->findByName($countryName);
	$isoCountry = DAOReg::get('ISOCountryDAO')->findByPK($country->iso_code);
	$airports = (array) json_decode($isoCountry->airports);
	sort($airports);
	$smarty->assign('airports', $airports);
}

global
	$auth,
	$smarty,
	$app_address,
	$REMITTER_ID_TYPES,
	$REMITTER_ID_TYPES_2,
	$REMITTER_ID_TYPES_3,
	$REMITTER_ID_TYPES_4,
	$CONFIG_ALLOW_ADMIN_TO_BYPASS_MEMBER_COMPLIANCE,
	$ALLOW_AGENT_TO_CHANGE_STATUS_REMITTER,
	$CONFIG_REMITTER_GROUPS,
	$REMITTER_ID_TYPE_2_EXPIRY,
	$REMITTER_ONE_NAME,
	$REMITTER_SECONDARY_ID_TYPES,
	$REMITTER_ID_DISCLAIMER,
	$REMITTER_CONSENT_LETTER,
	$REMITTER_EDUCATION,
	$REMITTER_SECTOR,
	$REMITTER_MARITAL_STATUS,
	$REMITTER_OTHER_CONTACT_DETAILS,
	$REMITTER_ADDITIONAL_INFORMATION,
	$CONFIG_EMAIL_RECEIPT_TO_REMITTER,
	$ALLOW_AGENT_TO_CHOOSE_GROUP,
	$SHOW_REMITTER_STATUS_DROPDOWN_TO_AGENT,
	$ID_VERIFICATION_ON_ALL_MEMBERS,
	$REMITTER_NATIONALITY_DEFAULT,
	$INCLUDE_REMITTER_NATIONALITY_AUTO_SELECT,
	$ONLY_ADMIN_VIEW_AND_AMEND_REMITTER_SUSPICIOUS_REASON,
	$CONFIG_POSTCODEANYWHERE,
	$PCA_PREDICT_CONFIG,
	$remitterBuildingNumberTargetField,
	$EDIT_OBSERVATION_FIELD_ALLOWED_USER_TYPES,
	$ADDRESS3_AS_DROPDOWN,
	$REMITTER_SCANS_DIR,
	$REMITTER_VIDEO_DIR,
	$CONFIG_FORMS_BASE,
	$CONFIG_HIDE_ID_FROM_TELLERS,
	$HIDE_ID_SCAN_DETAILS_NON_HQ_AGENTS,
	$USER_LOCKOUT_PERIOD,
	$COMPLIANCE_RISK_SCORING,
	$REMITTER_DEFAULTS,
	$EMIRATES_ID_READER,
	$CONFIG_REMITTER_OCCUPATION_DROPDOWN,
    $VISA_STATUS_LIST,
	$PROVINCES_AS_DROPDOWN,
	$CITIES_AS_DROPDOWN;

	$custom_perm = ! empty( $_REQUEST['member_id'] ) && $_REQUEST['member_id']!='AUTO'
		? 'edit_remitters'
		: 'add_remitters';

if(!(
	in_array($auth->user_type(), array('Admin', 'Admin_Limited', 'Admin_Support', 'Admin_Processing', 'Admin_Compliance'))
		|| (in_array($auth->user_type(), array('Agent', 'Agent_Subuser', 'Agent_Teller')) && $auth->hasBidiPermission("CREATE")=='t') 
		|| ($auth->user_type()=="Admin_Custom" && $auth->hasPermission($custom_perm))
		|| ($auth->user_type()=='Agent_Limited' && $auth->hasPermission($custom_perm))
)) {
	$smarty->display('not_authorised.tpl');
	exit(1);
}

if(isset($_GET['fx'])) {
	$smarty->assign('fx', 'true');
}
else {
	$smarty->assign('fx', 'false');
}

setCountryCode();

if ($_POST['get_agents_list'] == true) {
	$agents = DAOReg::get('AgentDAO')->findInCountry($_POST['country']);
	$smarty->assign('agents', $agents);
	$smarty->display('modules/agents_list.tpl');
	exit(0);
} else if ($_POST['set_ID_types'] == true) {
	$allowedUserTypes = array('Admin','Admin_Limited','Admin_Custom','Admin_Read','Admin_Compliance','Admin_Processing','Admin_Support','Accounts');
	if(empty($auth) || !in_array($auth->user_type(), $allowedUserTypes)){
		exit(0);
	}
	
	if($auth->user_type()=='Admin_Custom' && !$auth->hasPermission('edit_remitters')) {
		exit(0);
	}
	
	$countryName = $_POST['country'];
	$sourceCountryCode = DAOReg::get('DDCountryDAO')->findByName($countryName, 'source')->country_code;
	GenUtil::setRemitterIDs($sourceCountryCode, 'Agent'); // Pretend to be an agent (shhh!)
	
	$remitterIDTypes = array(
			'REMITTER_ID_TYPES' => $REMITTER_ID_TYPES,
			'REMITTER_ID_TYPES_2' => $REMITTER_ID_TYPES_2,
			'REMITTER_ID_TYPES_3' => $REMITTER_ID_TYPES_3,
			'REMITTER_ID_TYPES_4' => $REMITTER_ID_TYPES_4,
		);
	
	echo json_encode($remitterIDTypes);
	exit(0);
} else if ($_POST['get_airports_list'] == true) {
	$country = DAOReg::get('DDCountryDAO')->findByName($_POST['country']);
	$isoCountry = DAOReg::get('ISOCountryDAO')->findByPK($country->iso_code);
	$airports = (array) json_decode($isoCountry->airports);
	sort($airports);
	$smarty->assign('airports', $airports);
	$smarty->display('modules/airports_list.tpl');
	exit(0);
}

// To handle deleting of ID document scans
if($_POST['deleteDocumentScan']==true){
	// Perform checking that the logged in user can delete this users scans
	$allowed = false;
	$member = null;

	try	{
		if(
			empty($auth) ||
			!in_array($auth->user_type(), array('Agent', 'Admin', 'Admin_Custom', 'Agent_Teller')) ||
			($auth->user_type()=='Admin_Custom' && !$auth->hasPermission('edit_remitters'))
		){
			throw new Exception(Translate::getValue('validation.remitter.insufficient_privileges'));
		} else {
			// At least logged in so start by getting the remitter
			$member = new RemitterModel();
			$remitterID = $_POST['remitterID'];
			$scanIdNumber = $_POST['scanIDNumber'];
			$member->load($remitterID);
			
			// The auth logic is taken from the check_access.php file
			// I'm so so sorry about the horrible if/else flow, couldn't be helped :(
			if(in_array($auth->user_type(), array('Agent', 'Agent_Teller'))) {
				$agents_see_other_remitters = GenUtil::agentsSeeOtherRemitters();
			
				if($member == null)	{
					throw new Exception(Translate::getValue('validation.remitter.does_not_exist'));
				} else if (!array_key_exists($scanIdNumber, $member->getDataArray())) { // not valid scanID (field)
					throw new Exception(Translate::getValue('validation.remitter.invalid_scan_id', $scanIdNumber));
				} else if($agents_see_other_remitters == 'ALL' && $member->country = $auth->country()) {
					//Agents are allowed to see all remitters within the same country is on, and member is in the same country as agent user
					$allowed = true;
				} else if($agents_see_other_remitters == 'APPROVED') {
					// if Agents can only see their own members, or those members that have been approved by the admin
					$allowed = RemitterService::allowAgentAccessToRemitter($auth->user_id(), $member->member_id);
				}
				// if a member doesn't belong to this agent or above conditions failed, access is restricted
				if($member->agent_id == $auth->user_id() || $allowed) {
					$allowed = true;
				} else {
					throw new Exception(Translate::getValue('validation.remitter.insufficient_privileges'));
				}
			} else {
				// If it's an Admin user
				$allowed = true;
			}
		}

		// If they reach here, then they have enough access so proceed
		$scanIdFileName = $member->$scanIdNumber;
		$member->$scanIdNumber = "";
		$member->update(); // remove filename from member
		// Delete the file from disk
		if(is_file($base_dir . $REMITTER_SCANS_DIR . $scanIdFileName)) {
			RemitterService::deleteOldScanFile($scanIdFileName, "");
			RemitterService::deleteOldScanFile("ignore", "ignore", true, $remitterID);
		} else {
			throw new Exception(Translate::getValue('validation.remitter.success_delete_file_but_unable_to_find_file'));
		}
		$scanIdNumber = strtoupper($scanIdNumber);
		echo "<br/>" . Translate::getValue('validation.remitter.success_delete_file', $scanIdNumber);

	} catch (Exception $e)	{
		echo "<br/>{$e->getMessage()}";
	}
	exit(0);
}

// To handle deleting of KYC Video
if($_POST['deleteKYCVideo'] == true) {
	// Perform checking that the logged in user can delete this users scans
	$allowed = false;
	$member = null;

	try	{
		if(
			empty($auth) ||
			!in_array($auth->user_type(), array('Agent', 'Admin', 'Admin_Custom', 'Agent_Teller')) ||
			($auth->user_type()=='Admin_Custom' && !$auth->hasPermission('edit_remitters'))
		){
			throw new Exception(Translate::getValue('validation.remitter.insufficient_privileges'));
		} else {
			// At least logged in so start by getting the remitter
			$member = new RemitterModel();
			$remitterID = $_POST['remitterID'];
			$member->load($remitterID);
			
			// The auth logic is taken from the check_access.php file
			// I'm so so sorry about the horrible if/else flow, couldn't be helped :(
			if(in_array($auth->user_type(), array('Agent', 'Agent_Teller'))) {
				if($member == null)	{
					throw new Exception(Translate::getValue('validation.remitter.does_not_exist'));
				} else if($agents_see_other_remitters == 'ALL' && $member->country = $auth->country()) {
					//Agents are allowed to see all remitters within the same country is on, and member is in the same country as agent user
					$allowed = true;
				} else if($agents_see_other_remitters == 'APPROVED') {
					// if Agents can only see their own members, or those members that have been approved by the admin
					$allowed = RemitterService::allowAgentAccessToRemitter($auth->user_id(), $member->member_id);
				}
				// if a member doesn't belong to this agent or above conditions failed, access is restricted
				if($member->agent_id == $auth->user_id() || $allowed) {
					$allowed = true;
				} else {
					throw new Exception(Translate::getValue('validation.remitter.insufficient_privileges'));
				}
			} else {
				// If it's an Admin user
				$allowed = true;
			}
			
			// If they reach here, then they have enough access so proceed
			$kycvideo = $member->kyc_video;
			$member->kyc_video = "";
			$member->update(); // remove filename from member
			
			if (!empty($kycvideo)) {
				$kycvideo = json_decode($kycvideo);
			}
			
			// Delete the file from disk
			if(is_file($base_dir . $REMITTER_VIDEO_DIR . $kycvideo->video)) {
				RemitterService::deleteOldKYCVideoFile($kycvideo->video, "");
				RemitterService::deleteOldKYCVideoFile("ignore", "ignore", true, $remitterID);
			} else {
				throw new Exception(Translate::getValue('validation.remitter.success_delete_video_but_unable_to_find_file'));
			}

			echo "<br/>" . Translate::getValue('validation.remitter.success_delete_video');
		}
	} catch (Exception $e)	{
		echo "<br/>{$e->getMessage()}";
	}
	exit(0);
}

// if there is a POST then this is a create or an update :
if (count($_POST)>0) {
	
	RemitterService::checkRemitterAddress1($_POST);

	// TODO: refactor this into lower level class
	if (isset($_POST['visa_status'])) $_POST['visa_status'] = strtoupper($_POST['visa_status']);

    try {
		
		DBTx::begin();

		// if this is an admin user, then set CONFIG_FORMS to the country of the submitted remitter :
		if (in_array($auth->user_type(), array('Admin','Admin_Limited','Admin_Custom'))) {
			$CONFIG_FORMS = GenUtil::generateCONFIG_FORMS($_POST['country']);
		}
		assignAgentsToSmarty($smarty, $_POST['country']);
		setRemitterIDTypes($auth);
		getAirportsList($smarty, $_POST['country']);
		
		
        if ($_POST['member_id']!=null and $_POST['member_id']!='AUTO') {
		//------------------------------------------------------------------
		// update :
			CSRF::checkToken('AuthUser.allForms');
			
			if($auth->user_type()=='Admin_Custom' && !$auth->hasPermission('edit_remitters')) {
				$smarty->display('not_authorised.tpl');
				exit(0);
			}
			
			if($auth->user_type()=='Agent_Limited' && !$auth->hasPermission('edit_remitters')) {
				$smarty->display('not_authorised.tpl');
				exit(0);
			}

			$smarty->assign('title', Translate::getValue('title.remitter.edit'));
			$member = getMember($_POST['member_id']);
			$smarty->assign('member', $member);
            if ($member != null) {
                $compare = new \remitone\util\Comparative();
                $auditTrailMessage = [];
				
				if(in_array($auth->user_type(), array('Agent','Agent_Teller','Agency'))){
					$_POST['agent_id'] = $member->agent_id;
				}

				// sort out admin-set suspicious flag :
				if (
					$member->suspicious =='f' &&
					$_POST['suspicious'] =='t' &&
					in_array(
						$auth->user_type(),
						array('Admin','Admin_Limited','Admin_Custom','Admin_Compliance','Admin_Processing')
					)
				) {
					$_POST['admin_marked_suspicious']='t';
				} else if (
					$member->suspicious =='t' &&
					!isset($_POST['suspicious']) &&
					in_array(
						$auth->user_type(),
						array('Admin','Admin_Limited','Admin_Custom','Admin_Compliance','Admin_Processing')
					)
				) {
					$_POST['admin_marked_suspicious']='f';
				}			
				
				// Make sure that only allowed users can bypass blacklist compliance
				if(isset($_POST['compliance_whitelist']) 
					&& (!$CONFIG_ALLOW_ADMIN_TO_BYPASS_MEMBER_COMPLIANCE 
						|| !in_array($auth->user_type(), array('Admin', 'Admin_Compliance', 'Admin_Limited', 'Admin_Custom'))
						|| ($auth->user_type()=='Admin_Custom' && !$auth->hasPermission('toggle_compliance_bypass')))) {
					throw new Exception(Translate::getValue('validation.remitter.compliance_whitelist_unauthorised'));
				}

				// Ensure that an agent cannot change the status of a remitter if he is not allowed
				if (
					!$ALLOW_AGENT_TO_CHANGE_STATUS_REMITTER &&
					$member->status != $_POST['status'] &&
					in_array($auth->user_type(), array('Agent', 'Agent_Teller'))
				) {
					throw new Exception(Translate::getValue('validation.remitter.status_change_requires_admin'));
				}
				
				$remitterModel = RemitterBaseModel::getRemitterModel($_POST['member_id']);	
				if($remitterModel->isTempMember()) {
					// The service will convert this remitter to registered
					$_POST['type'] = 'quickregistered';
					
					// We need to transform this TempMember in full Member
					RemitterService::createRemitter($_POST, $_FILES);

					// Remove the temporary member as we will now have a full Member
					$remitterModel->delete();
				}
				else {				
					if ('Individual' == $_POST['orgtype']) {
						$_POST['company_name'] = '';
						$_POST['company_type'] = '';
						$_POST['company_reg_no'] = '';
						$_POST['allow_forward_deals'] = false;
						$_POST['allow_special_rate'] = false;
						
					}
					
					if (empty($_POST['allow_forward_deals'])) {
						$_POST['allow_forward_deals'] = false;
					}
					if (empty($_POST['allow_special_rate'])) {
						$_POST['allow_special_rate'] = false;
					}
					
					if (!empty($_POST['country_of_birth'])) {
						$_POST['country_of_birth'] = DAOReg::get("ISOCountryDAO")->findByName($_POST['country_of_birth'])->iso_code;
					}
					
					// only Admin users and the member's Agent can edit the referral_code
					if (isset($_POST['referral_code']) && !in_array($auth->user_type(), array('Admin','Admin_Limited','Admin_Custom','Admin_Processing')) && $remitterModel->agent_id!=$auth->user_id()) {
						$_POST['referral_code'] = $remitterModel->referral_code;
					}
					
					RemitterService::updateRemitter($_POST, $_FILES);
				}
				
				
				$memberDAO = new MemberDAO();
				$memberDAO->checkMemberExpiration($_POST['member_id']);
				
				// Eventually promote only if authorised
				if(
					(
						in_array($auth->user_type(), array('Agent', 'Agent_Teller')) &&
						$ALLOW_AGENT_TO_CHANGE_STATUS_REMITTER
					) ||
					!in_array($auth->user_type(), array('Agent', 'Agent_Teller'))
				) {
					$memberDAO->checkMemberValidation($_POST['member_id']);
				
					// Verify that the remitter status is coherent with the eventual ID expiry dates
					RemitterService::verifyStatusAgainstExpiryDates((array) $memberDAO->findByPK($_POST['member_id']));
				}
				
				$memberDAO->checkIDVerificiationExpiration();
				
				// The remitter was updated successfully so now check if it was updated via a transaction and if so
				// update all the remitter details on the transaction
				if (
				    isset($_GET['remit_trans_id']) &&
                    in_array(
                        $auth->user_type(),
                        array('Admin', 'Admin_Limited', 'Admin_Custom', 'Admin_Support', 'Admin_Processing')
                    ) &&
                    $_GET['remit_trans_id'] !== '' &&
                    GenUtil::isWholeNumber($_GET['remit_trans_id'])
                ) {
					$remitterModel = new RemitterModel();
					$remitterModel->load($_POST['member_id']); // directly off POST as only admin types can access here
					
					$transUpdate['trans_id'] = $_GET['remit_trans_id'];
					$transUpdate['remitt_name'] = $remitterModel->getFullName();
					$transUpdate['remitt_addr'] = $remitterModel->getFullAddress();
					$transUpdate['remitt_tel'] = $remitterModel->telephone;
					$transUpdate['remitt_mobile'] = $remitterModel->mobile;
					$transUpdate['remitt_id_type'] = $remitterModel->id1_type;
					$transUpdate['remitt_id_details'] = $remitterModel->id1_details;
					$transUpdate['remitt_nationality'] = $remitterModel->nationality;
					
					foreach ($transUpdate as $key => $remittValue) {
						$transUpdate[$key] = strtoupper($remittValue);
					}

                    /* @var $transactionDAO TransactionDAO */
                    $transactionDAO = DAOReg::get('TransactionDAO');
					$transactionOld = (array) $transactionDAO->findByPK($_GET['remit_trans_id']);
					$transactionDAO->update($transUpdate);
					$transactionNew = (array) $transactionDAO->findByPK($_GET['remit_trans_id']);
                    $transactionResults = $compare->getDifferenceBetweenOfArrays($transactionOld, $transactionNew);
                    $auditTrailMessage['other_data']['transaction']['id'] = $_GET['remit_trans_id'];
                    $auditTrailMessage['other_data']['transaction']['trans_ref'] = $transactionOld->trans_ref;
                    $auditTrailMessage['original_data']['transaction'] = $transactionResults['original_data'];
                    $auditTrailMessage['changed_data']['transaction'] = $transactionResults['changed_data'];
				}

                $memberOld = (array) $member;
                $memberNew = (array) getMember($_POST['member_id']);
				
				$memberResults = $compare->getDifferenceBetweenOfArrays($memberOld, $memberNew);
                $auditTrailMessage['other_data']['member']['id'] = $_POST['member_id'];
                $auditTrailMessage['other_data']['member']['full_name'] = $memberOld['name_ordered'];
                $auditTrailMessage['original_data']['member'] = $memberResults['original_data'];
                $auditTrailMessage['changed_data']['member'] = $memberResults['changed_data'];
				
	            AuditTrailLogger::logFromArray(
		            [
			            'event_category' => 'update_remitter',
			            'auth' => (isset($auth) && $auth instanceof ExtAuth) ? $auth : false,
			            'message' => "Remitter '{$_POST['member_id']}' updated by __USERNAME__",
			            'original_data' => json_encode($auditTrailMessage['original_data'], JSON_PRETTY_PRINT),
			            'changed_data' => json_encode($auditTrailMessage['changed_data'], JSON_PRETTY_PRINT)
		            ]
	            );
				$message = Translate::getValue('validation.remitter.success_updated', $_POST['member_id']);
				FlashMessages::addFlashMessage($message);
				$remitTransGet = isset($_GET['remit_trans_id']) ? "&remit_trans_id={$_GET['remit_trans_id']}" : '';
				$remitFxGet = isset($_GET['fx']) ? "&fx" : '';
				
				DBTx::commit();
				
				if($auth->user_type()=='Admin_Custom' && !$auth->hasPermission('search_remitters')) {
					header('Location: ./index.php');
				}
				else {
					header(
						'Location: ./member_view.php?member_id=' . $_POST['member_id'] .
						'&viewtype=' . $_POST['viewtype'] . '&close_after_edit=' . $_REQUEST['close_after_edit'] .
						$remitTransGet . $remitFxGet
					);
				}
				
				exit(0);
			}
        } else {
		//------------------------------------------------------------------
		// create :
			CSRF::checkToken('AuthUser.allForms');
			
			if($auth->user_type()=='Admin_Custom' && !$auth->hasPermission('add_remitters')) {
				$smarty->display('not_authorised.tpl');
				exit(0);
			}
			
			if($auth->user_type()=='Agent_Limited' && !$auth->hasPermission('add_remitters')) {
				$smarty->display('not_authorised.tpl');
				exit(0);
			}
			$smarty->assign('title', Translate::getValue('title.remitter.add'));
			if (in_array($auth->user_type(), array('Agent','Agent_Teller'))) {
				$_POST['agent_id'] = $auth->user_id();
				
				if($auth->is_agent_teller()) {
					$_POST['operator_id'] = $auth->real_user_id();
				}
				else {
					$_POST['operator_id'] = null;
				}
			}
            $_POST['member_id'] = '';
			
			if($_POST['agent_id']==''){
				throw new Exception(Translate::getValue('validation.remitter.agent_not_found'));
			}

			if($_POST['national_id_number']=='' && !in_array($_POST['id1_type'], ['Altro', 'EU ID', 'Passaporto'])) {
				throw new Exception(Translate::getValue('validation.remitter.national_id_required'));
			}
			
			// sort out admin-set suspicious flag :
			if (
				$_POST['suspicious'] =='t' &&
				in_array(
					$auth->user_type(),
					array('Admin','Admin_Limited','Admin_Custom','Admin_Compliance','Admin_Processing')
				)
			) {
				$_POST['admin_marked_suspicious']='t';
			}
			
			// Verify that the remitter status is coherent with the eventual ID expiry dates
			RemitterService::verifyStatusAgainstExpiryDates($_POST);
			
            $new_remitter_id = RemitterService::createRemitter($_POST, $_FILES);

			DBTx::commit();
			
			if ($_POST['destcountryid']!='') {
				// this is a step-by-step transaction creation, so redirect to the start trans screen :
				header("Location: ./trans_new.php?destcountryid=".$_POST['destcountryid']."&set_member_id=$new_remitter_id");
			} else {
				$message = "Member Successfully Added : $new_remitter_id<br/><a href=\"benef_new.php?member_id=$new_remitter_id\">Add a Beneficiary</a> to this Remitter";
				FlashMessages::addFlashMessage($message);
				$smarty->assign('m_member_id', $new_remitter_id);
				
				if(isset($_GET['fx'])) {
					header('Location: ./FxTransaction_displayNewFxTransaction.php?member_id='.$new_remitter_id);
					exit;
				}
				
				if($auth->user_type()=='Admin_Custom' && !$auth->hasPermission('search_remitters')) {
					header('Location: ./index.php');
				}
				else {
					header('Location: ./member_view.php?member_id='.$new_remitter_id.'&viewtype='.$_POST['viewtype']);
				}
			}
            exit(0);
        }
    } 
	catch (ValidationException $e) {
		DBTx::rollback();
		$smarty->assign('validationErrors', $e->getErrorMessages());
		
		$data = $_POST;
		if ($member!=null) {
			$data = array_merge((array)$member, $data);
		}
		$smarty->assign('data', $data);
		
		if (!empty($_POST['member_id']) && $_POST['member_id'] != 'AUTO') {
			if ($member->type != 'quickregistered' && $COMPLIANCE_RISK_SCORING['enabled']==true && $COMPLIANCE_RISK_SCORING['remitter']['enabled']==true) {
				$remitterRiskScore = new MemberRiskScoreModel();
				$remitterRiskScore->loadByMemberId($member->member_id);
				$smarty->assign('remitterRiskScore', $remitterRiskScore);
			}
		}
		
		if($CONFIG_REMITTER_GROUPS['ENABLED'] == true) {
			$groups = DAOReg::get('GroupsDAO')->getEnabledGroups();
			$smarty->assign('groups', $groups);	
			$groupsSelected = $_POST['groups_array'];
			$smarty->assign('groups_array', $_POST['groups_array']);
		}
	}
	catch (Exception $e) {
		DBTx::rollback();
		$smarty->assign('error', $e->getMessage());
		
		$data = $_POST;
		if ($member!=null) {
			$data = array_merge((array)$member, $data);
		}
		$smarty->assign('data', $data);
		
		if (!empty($_POST['member_id']) && $_POST['member_id'] != 'AUTO') {
			if ($member->type != 'quickregistered' && $COMPLIANCE_RISK_SCORING['enabled']==true && $COMPLIANCE_RISK_SCORING['remitter']['enabled']==true) {
				$remitterRiskScore = new MemberRiskScoreModel();
				$remitterRiskScore->loadByMemberId($member->member_id);
				$smarty->assign('remitterRiskScore', $remitterRiskScore);
			}
		}
		
		if($CONFIG_REMITTER_GROUPS['ENABLED'] == true) {
			$groups = DAOReg::get('GroupsDAO')->getEnabledGroups();
			$smarty->assign('groups', $groups);	
			$groupsSelected = $_POST['groups_array'];
			$smarty->assign('groups_array', $_POST['groups_array']);
		}
		
	}

} else {
	
	//--------------------------------------------------------------------------
    // This is a GET, which can be a new form or view details of existing member :
    if($_REQUEST['member_id']) {
        // existing member :
		
		// Check permissions
		if($auth->user_type()=='Admin_Custom' && !$auth->hasPermission('edit_remitters')) {
			$smarty->display('not_authorised.tpl');
			exit(0);
		}

		
		
		//Check if he is pending approval
		$linkMemberDAO = DAOReg::get('LinkMembersDAO');				
		$pending_link = $linkMemberDAO->findByLinkExistanceAndPendingApprovalOnTempMembersOnly($_REQUEST['member_id']);
		if (!empty($pending_link)) {
			header('Location: ./member_view.php?member_id=' . $_REQUEST['member_id'] . '&linkError=1');
			exit;
		}
		
        $smarty->assign('title', Translate::getValue('title.remitter.edit'));
		$member = getMember($_REQUEST['member_id']);
        $smarty->assign('data', (array) $member);
		
		// Data may be overriden by the user. But we still want to access the original values
		$smarty->assign('member', $member);
		
		if ($member->type != 'quickregistered' && $COMPLIANCE_RISK_SCORING['enabled']==true && $COMPLIANCE_RISK_SCORING['remitter']['enabled']==true) {
			$remitterRiskScore = new MemberRiskScoreModel();
			$remitterRiskScore->loadByMemberId($member->member_id);
			$smarty->assign('remitterRiskScore', $remitterRiskScore);
		}
		
		// if this is an admin user, then set CONFIG_FORMS to the country of the submitted remitter :
		if (in_array($auth->user_type(), array('Admin','Admin_Limited','Admin_Custom'))) {
			$CONFIG_FORMS = GenUtil::generateCONFIG_FORMS($member->country);
		}
		setRemitterIDTypes($auth);
		assignAgentsToSmarty($smarty, $member->country);
		getAirportsList($smarty, $member->country);
		
		if($CONFIG_REMITTER_GROUPS['ENABLED'] == true) {
			$groupsSelected = DAOReg::get('GroupMembersDAO')->getMemberGroupIDs($_REQUEST['member_id']);
			$smarty->assign('groups_array', $groupsSelected);
		}
		
    } else {
        // new form :
		
		// Check permissions
		if($auth->user_type()=='Admin_Custom' && !$auth->hasPermission('add_remitters')) {
			$smarty->display('not_authorised.tpl');
			exit(0);
		}
	    $data = [];
		if ($REMITTER_ID_TYPE_2_EXPIRY!=null) {
			// set default expiry date for secondary ID :
			$today = getdate( time() + ($REMITTER_ID_TYPE_2_EXPIRY * 24 * 60 * 60) );
			$data['id2_expiry'] = $today['year'].'-'.$today['mon'].'-'.$today['mday'];
		}
		
		if (isset($_GET['corporateCountry'])) {
			$corporateCountryData = DAOReg::get('DDCountryDAO')->findByName($_GET['corporateCountry']);
			
			$data['country'] = $_GET['corporateCountry'];
			$data['country_code'] = $corporateCountryData->country_code;
		}
		
		if (isset($_GET['representative']) && isset($_GET['corporateMember'])) {
			$data['representative'] = 't';
			$data['linked_corporate_remitter'] = $_GET['corporateMember'];
			$data['orgtype'] = 'Individual';
			$data['type'] = 'registered';
		}
		
		$smarty->assign('data', $data);
		$smarty->assign('new_form', true);
        $smarty->assign('title', Translate::getValue('title.remitter.add'));
		
		if($CONFIG_REMITTER_GROUPS['ENABLED'] == true){
			$groups = DAOReg::get('GroupsDAO')->getEnabledGroups();
			$smarty->assign('groups', $groups);
		}
    }
}

$allCountries = DAOReg::get("DDCountryDAO")->getAllCountries();
$smarty->assign('allCountries', $allCountries);

// set various things :
get_countries("SOURCE");

$isoCountriesDAO = new ISOCountryDAO();
$isoCountries = $isoCountriesDAO->getAll();
$smarty->assign('isoCountries', $isoCountries);

// get and assign all transfer purposes
$smarty->assign('transferPurposes', GenUtil::arrayOfObjectsToSingleArray(DAOReg::get('DDPurposeDAO')->findAll(), 'name'));

if($CONFIG_REMITTER_GROUPS['ENABLED']  == true) {
	$groups = DAOReg::get('GroupsDAO')->getEnabledGroups();
	$smarty->assign('groups', $groups);
	$smarty->assign('CONFIG_REMITTER_GROUPS', $CONFIG_REMITTER_GROUPS);	
}

if ($CONFIG_REMITTER_OCCUPATION_DROPDOWN['enabled']) {
	$smarty->assign('remitter_occupation_values', $CONFIG_REMITTER_OCCUPATION_DROPDOWN['dropdown_values']);
	$smarty->assign('remitter_occupation_dropdown', true);
}

$smarty->assign('VISA_STATUS_LIST', $VISA_STATUS_LIST);

$ddCountriesDAO = new DDCountryDAO();
$ddCountries = $ddCountriesDAO->getByDeliveryMechanism('DEFAULT', true);
$smarty->assign('ddCountries', $ddCountries);
$smarty->assign('REMITTER_ONE_NAME', $REMITTER_ONE_NAME);
$smarty->assign('REMITTER_ID_TYPES', $REMITTER_ID_TYPES);
$smarty->assign('REMITTER_ID_TYPES_2', $REMITTER_ID_TYPES_2);
$smarty->assign('REMITTER_ID_TYPES_3', $REMITTER_ID_TYPES_3);
$smarty->assign('REMITTER_ID_TYPES_4', $REMITTER_ID_TYPES_4);
$smarty->assign('REMITTER_SECONDARY_ID_TYPES', $REMITTER_SECONDARY_ID_TYPES);
$smarty->assign('REMITTER_ID_DISCLAIMER', $REMITTER_ID_DISCLAIMER);
$smarty->assign('REMITTER_CONSENT_LETTER', $REMITTER_CONSENT_LETTER);
$smarty->assign('REMITTER_EDUCATION', $REMITTER_EDUCATION);
$smarty->assign('REMITTER_SECTOR', $REMITTER_SECTOR);
$smarty->assign('REMITTER_MARITAL_STATUS', $REMITTER_MARITAL_STATUS);
$smarty->assign('REMITTER_OTHER_CONTACT_DETAILS', $REMITTER_OTHER_CONTACT_DETAILS);
$smarty->assign('REMITTER_ADDITIONAL_INFORMATION', $REMITTER_ADDITIONAL_INFORMATION);
$smarty->assign('CONFIG_EMAIL_RECEIPT_TO_REMITTER', $CONFIG_EMAIL_RECEIPT_TO_REMITTER['enabled']);
$smarty->assign('ALLOW_AGENT_TO_CHOOSE_GROUP', $ALLOW_AGENT_TO_CHOOSE_GROUP);
$smarty->assign('ALLOW_AGENT_TO_CHANGE_STATUS_REMITTER', $ALLOW_AGENT_TO_CHANGE_STATUS_REMITTER);
$smarty->assign('SHOW_REMITTER_STATUS_DROPDOWN_TO_AGENT', $SHOW_REMITTER_STATUS_DROPDOWN_TO_AGENT);
$smarty->assign('ID_VERIFICATION_ON_ALL_MEMBERS', $ID_VERIFICATION_ON_ALL_MEMBERS);
$smarty->assign('CONFIG_ALLOW_ADMIN_TO_BYPASS_MEMBER_COMPLIANCE', $CONFIG_ALLOW_ADMIN_TO_BYPASS_MEMBER_COMPLIANCE);
$smarty->assign('CONFIG_MINIMIZE_UI', $CONFIG_MINIMIZE_UI);
$smarty->assign('CONFIG_UI_ENTER2TAB', $CONFIG_UI_ENTER2TAB);
$smarty->assign('defaultIdTypeByOrgtypeJSON', json_encode($REMITTER_DEFAULTS['default_id_type_by_orgtype']));
$smarty->assign('HIDE_ID_SCAN_DETAILS_NON_HQ_AGENTS', $HIDE_ID_SCAN_DETAILS_NON_HQ_AGENTS);

// For enter2tab :
$nextFieldOrderJSON = json_encode($CONFIG_FORMS_FIELD_ORDER['new_member']);
$smarty->assign('nextFieldOrderJSON', $nextFieldOrderJSON);

// set up remitter nationality default :
$source_country_name = $auth->country();
if ($REMITTER_NATIONALITY_DEFAULT[$source_country_name]=='' && $INCLUDE_REMITTER_NATIONALITY_AUTO_SELECT=="true") {
	// set this country in the array :
	$source_country = $isoCountriesDAO->findByPrintableName($source_country_name);
	$REMITTER_NATIONALITY_DEFAULT[$source_country_name] = $source_country->iso_code;
}
$smarty->assign('REMITTER_NATIONALITY_DEFAULT', $REMITTER_NATIONALITY_DEFAULT);

$browserDetails = BrowserDetector::detect();
$userSessionAgent = strtoupper($auth->getUserSession()['sessionuseragent']);
if ($browserDetails['name'] != 'chrome' && !strpos($userSessionAgent, 'WINDOWS')) {
	$EMIRATES_ID_READER = false;
}
$smarty->assign('EMIRATES_ID_READER', $EMIRATES_ID_READER);

// if this is a step-by-step transaction then pass destcountryid on :
$smarty->assign('destcountryid', $_REQUEST['destcountryid']);

$smarty->assign('postcodeanywhereEnabled', $CONFIG_POSTCODEANYWHERE['enabled']);
$smarty->assign('PCAPredictEnabled', $PCA_PREDICT_CONFIG['enabled']);
$smarty->assign('PCAPredict', $PCA_PREDICT_CONFIG);
$smarty->assign('app_address', $app_address);
$smarty->assign('language', $_SESSION['language']);
$smarty->assign('hear_about_us_options', DAOReg::get('HearAboutUsDAO')->findAllEnabled());

//purpose stuff
$purposes = DAOReg::get('DDPurposeDAO')->getPurposes();
$smarty->assign('purposes', $purposes);
$purposes_array = array();
foreach($purposes as $p) {
	$purposes_array[] = $p->name;
}
$smarty->assign('purposes_array', $purposes_array);

//$purpose = $AGENT_DEFAULTS['create_transaction']['purpose'];
//$smarty->assign('purpose', $purpose);

// source of income stuff
$smarty->assign('sources_of_income', DAOReg::get('DDSourceOfIncomeDAO')->getAll());
$sources_of_income = DAOReg::get('DDSourceOfIncomeDAO')->getAll();
$sources_of_income_array = array();
foreach($sources_of_income as $src) {
	$sources_of_income_array[] = $src->name;
}
$smarty->assign('sources_of_income_array', $sources_of_income_array);

if(trim($remitterBuildingNumberTargetField) !== "") {
	$smarty->assign('remitterBuildingNumberTargetField', $remitterBuildingNumberTargetField);
}

// hide blacklist result
$hideBlackListResult = GenUtil::hideBlackListFromAgent();
$smarty->assign('hide_blacklist_result', $hideBlackListResult);
$smarty->assign('ONLY_ADMIN_VIEW_AND_AMEND_REMITTER_SUSPICIOUS_REASON', $ONLY_ADMIN_VIEW_AND_AMEND_REMITTER_SUSPICIOUS_REASON);
$smarty->assign('HIDDEN_IDS', array());

if ($auth->user_type()=='Agent') {
	$countryIsoCode = $auth->country_iso_code();
} else if ($auth->user_type()=='Agent_Teller') {
	$countryIsoCode = $auth->country_iso_code();
	$country_id = $auth->country_id();
	if (isset($CONFIG_HIDE_ID_FROM_TELLERS[$country_id])) {
		$smarty->assign('HIDDEN_IDS', $CONFIG_HIDE_ID_FROM_TELLERS[$country_id]);
	}
} else if ($_POST['agent_id']!='') {
	$sourceAgent = new SourceAgentModel();
	$sourceAgent->load($_POST['agent_id']);
	$countryIsoCode = $sourceAgent->getAgentCountry()->iso_code;
} else if ($member != null) {
	// viewing an existing member
	$countryName = $member->country;
	$countryObj = DAOReg::get("DDCountryDAO")->findByName($countryName, 'SOURCE');
	$countryIsoCode = $countryObj->iso_code;
}

$smarty->assign("EDIT_OBSERVATION_FIELD_ALLOWED_USER_TYPES", $EDIT_OBSERVATION_FIELD_ALLOWED_USER_TYPES);
$smarty->assign('ADDRESS3_AS_DROPDOWN_ENABLED', $ADDRESS3_AS_DROPDOWN['enabled']);
$smarty->assign('ADDRESS3_AS_DROPDOWN_AREAS', $ADDRESS3_AS_DROPDOWN['AREAS'][$countryIsoCode]);
$smarty->assign('CONFIG_REMITTER_BANK_ACCOUNT', $CONFIG_REMITTER_BANK_ACCOUNT);
$smarty->assign('VERIFY_REMITTER_AND_BENEF_ACCOUNT_NUMBERS', $VERIFY_REMITTER_AND_BENEF_ACCOUNT_NUMBERS);
$smarty->assign('USER_LOCKOUT_PERIOD', $USER_LOCKOUT_PERIOD);

$verifyBVNNumber = 'f';
if(!in_array($auth->user_type(), array('Admin'))){
	if (is_array($BVN_NUMBER_SETTINGS['source_countries']) && in_array($auth->country_id(), $BVN_NUMBER_SETTINGS['source_countries'])) {
		$verifyBVNNumber = 't';
	}
}

$smarty->assign('verifyBVNNumber', $verifyBVNNumber);

if ($_REQUEST['viewtype'] === 'popup') {
	$smarty->assign('viewtype', "popup");
	$smarty->assign('m_fname', $_POST['fname']);
	$smarty->assign('m_mname', $_POST['mname']);
	$smarty->assign('m_lname', $_POST['lname']);
	$smarty->assign('m_address1', $_POST['address1']);
	$smarty->assign('m_address2', $_POST['address2']);
	$smarty->assign('m_city', $_POST['city']);
	$smarty->assign('m_state', $_POST['state']);
	$smarty->assign('m_telephone', $_POST['telephone']);
	$smarty->assign('m_mobile', $_POST['mobile']);
	$smarty->assign('m_email', $_POST['email']);
	$smarty->assign('m_id1_type', $_POST['id1_type']);
	$smarty->assign('m_id1_details', $_POST['id1_details']);
	$smarty->assign('m_id1_expiry', $_POST['id1_expiry']);
	$smarty->assign('m_id2_expiry', $_POST['id2_expiry']);
	$smarty->assign('m_id3_expiry', $_POST['id3_expiry']);
	$smarty->assign('m_id4_expiry', $_POST['id4_expiry']);
	$smarty->assign('m_id1_start', $_POST['id1_start']);
	$smarty->assign('m_id2_start', $_POST['id2_start']);
	$smarty->assign('m_id3_start', $_POST['id3_start']);
	$smarty->assign('m_id4_start', $_POST['id4_start']);
	$smarty->assign('m_status', $_POST['status']);
	$smarty->assign('m_type', $_POST['type']);
	$smarty->assign('member_type', $_POST['member_type']);
	$smarty->assign('close_after_edit', $_REQUEST['close_after_edit']);
	$smarty->display('member_new_popup.tpl');
} else {
	
	if ($CONFIG_FORMS_BASE['default']['remitter.registered.kyc_video.resize'] != true) {
		$post_max_size = ($CONFIG_FORMS_BASE['default']['remitter.registered.kyc_video.max_size'] / 1024) / 1024;
		$post_max_size .= ' MB';
	} else {
		$post_max_size = ini_get('upload_max_filesize');
		$last_char = substr($post_max_size,-1);
		if (in_array($last_char,array('M','G'))) {
			$post_max_size .= 'B';
		}
	}
	
	$customCountryDao = new CustomCountryNameDAO();
	$countries = $customCountryDao->findAll();

	$smarty->assign('member_type', $_GET['member_type']);
	$smarty->assign('video_max_size',$post_max_size);
	$smarty->assign('PROVINCES_AS_DROPDOWN_ENABLED',$PROVINCES_AS_DROPDOWN['enabled']);
	$smarty->assign('CITIES_AS_DROPDOWN_ENABLED',$PROVINCES_AS_DROPDOWN['enabled']);
	$smarty->assign('CUSTOM_COUNTRIES', json_encode($countries));

	$smarty->display('member_new.tpl');
}
