#!/usr/bin/php
<?php

include_once('../config.php');
include_once($base_dir . '/libs/genfuncs.php');
include_once($base_dir . 'libs/dbfuncs.php');
import_class('business/agent/CreditManager.php');
import_class('util/DataCacheService.php');
import_class('business/banks/ProcessingBankCreditModel.php');
use remitone\business\transaction\TransactionModel;

$creditManager = new CreditManager();
$transDAO = DAOReg::get('TransactionDAO');
$transactions = $transDAO->findTransactions('2021-01-01', '2023-12-31');


foreach ($transactions as $transactionData) {
    if ($transactionData->orig_source_currency !== null) {
        $transactionData->buy_rate = RateLookup::getConversionRate($transactionData->orig_source_currency, $transactionData->dest_currency);
        print_r($transactionData->trans_id . " - " . $transactionData->buy_rate . "\n");
        DBTx::begin();
        try {
            //update transactions
            $transactionModel = new TransactionModel();
            $transactionModel->load($transactionData->trans_id);
            $transactionModel->buy_rate = $transactionData->buy_rate;
            $transactionModel->update();
            DBTx::commit();
        } catch (Exception $e) {
            error_log("Exception: " . $e->getMessage());
            DBTx::rollback();
        }
    } else {
        $logMessage = "orig_source_currency is null for transaction: " . $transactionData->trans_id;
        error_log($logMessage);
    }
}

print_r("Búsqueda de transacciones y recalculos realizados con éxito.\n");

exit(0);
?>