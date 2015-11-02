#!/usr/bin/php
<?php
// 0.13
//
// PATH TO MAGENTO ROOT
//

if (!isset($argv[1])) {
    cliNotice('Usage: ' . $argv[0] . ' <magento path>');
    exit;
}


$_magentoPath = getcwd() . '/';
$magePhpPath  = $_magentoPath . '/app/Mage.php';

if (!file_exists($magePhpPath)) {
    cliError(sprintf('Magento not found in "%s"!', $magePhpPath));
    exit;
}

$_whiteListedConfigPaths = array(
    'web/unsecure/base_url',
    'web/secure/base_url',
    'trans_email/ident_support/name',
    'trans_email/ident_support/email',
    'trans_email/ident_general/name',
    'trans_email/ident_general/email',
    'trans_email/ident_sales/name',
    'trans_email/ident_sales/email',
    'trans_email/ident_custom1/name',
    'trans_email/ident_custom1/email',
    'trans_email/ident_custom2/name',
    'trans_email/ident_custom2/email',
    'general/store_information/name',
    'general/store_information/phone',
    'general/store_information/address',
);

$_whiteListedBlockTypes = array(
    'core/template',
    'catalog/product_new',
    'enterprise_catalogevent/event_lister',
);

// SECURITY PATCHES and APPSECS
//
$_securityPatches = array(
    'SUPEE-6788' => array
    (
        'APPSEC-1034' => array(
            'text'        => 'addressing bypassing custom admin URL',
            'exec'        => array(
                'path' => array(
                    $_magentoPath . 'app/code/community',
                    $_magentoPath . 'app/code/local'
                ),
                'cmds' => array(
                    'custom admin url' => 'grep -ro "<use>admin</use>" %s'
                )
            ),
            'magentopath' => $_magentoPath
        ),
        'APPSEC-1063' => array(
            'text'        => 'addressing possible SQL injection',
            'exec'        => array(
                'path' => array(
                    $_magentoPath . 'app/code/community',
                    $_magentoPath . 'app/code/local'
                ),
                'cmds' => array(
                    'addFieldToFilter with backtick'         => 'grep -ro "addFieldToFilter(\\\'\\`.*)" %s',
                    'addFieldToFilter with open parenthesis' => 'grep -ro "addFieldToFilter(\\\'(.*)" %s',
                )
            ),
            'magentopath' => $_magentoPath
        ),
        'APPSEC-1057' => array(
            'text'        => 'template processing method allows access to private information',
            'exec'        => array(
                'path' => array(
                    $_magentoPath . 'app/code/community',
                    $_magentoPath . 'app/code/local',
                    $_magentoPath . 'app/locale',
                    $_magentoPath . 'app/design/frontend'
                ),
                'cmds' => array(
                    'config path whitelist violation' =>
                        'grep -ro "{{config path=.*}}" %s | grep -v "' . implode('\|', $_whiteListedConfigPaths) . '"',
                    'block type whitelist violation'  =>
                        'grep -ro "{{block type=.*}}" %s | grep -v "' . implode('\|', $_whiteListedBlockTypes) . '"',
                )
            ),
            'magentopath' => $_magentoPath
        )
    )
);

// EXEC
//
echo '*** ' . "\033[1;32m" . 'Magento security file check' . "\033[0m" . ' ***' . "\n";
$_count = 1;

foreach ($_securityPatches as $_patchName => $_securityNotices) {
    echo $_patchName . "\n";
    $_total = 0;

    foreach ($_securityNotices as $_appsec => $_securityNotice) {
        $_count += 1;
        echo '[' . $_count . '] ' . $_appsec . ', ' . $_securityNotice['text'] . "\n";

        $_result = doExec($_securityNotice, $_appsec);
        $_total  = $_total + $_result['total'];

        echo $_result['text'] . "\n";

    }

    if ($_total == 0) {
        echo "$_patchName: 0 affected files.\n";
    } else {
        echo "$_patchName: \033[1;31m$_total\033[0m affected files.\n";
    }
}

echo '***********************************' . "\n";
exit;


function doExec($_securityNotice, $_appsec)
{
    $_text  = '';
    $_total = 0;

    foreach ($_securityNotice['exec']['path'] as $_searchPath) {
        if (!is_dir($_searchPath)) {
            cliNotice(sprintf('Path "%s" doesn\'t exist, skipping.', $_searchPath));
            continue;
        }
        $_text  = $_text . 'looking in ' . $_searchPath . "\n";
        $_count = 0;
        foreach ($_securityNotice['exec']['cmds'] as $_key => $_searchCommandTemplate) {
            $_output        = array();
            $_searchCommand = sprintf($_searchCommandTemplate, $_searchPath);
            exec($_searchCommand, $_output, $_status);

            if (1 === $_status) {
                $_text .= "$_key not found.\n";
                continue;
            }
            if (0 === $_status) {
                $_count += count($_output);
                $_total += $_count;

                $_text .= "{$_key} found;\033[1;31m {$_count} \033[0maffected files:\n";
                foreach ($_output as $_line) {
                    list($_filePath, $_match) = explode(':', $_line, 2);
                    $_fileName = str_replace($_securityNotice['magentopath'], ' ', $_filePath);
                    $_text .= "[\033[1;32m$_appsec\033[0m] $_match found in\033[1;31m$_fileName\033[0m\n";
                }
            } else {
                $_text .= "Command $_searchCommand failed with status: $_status\n";
            }

        }

    }

    return array(
        'text'  => $_text,
        'total' => $_total
    );
}


function cliError($msg)
{
    echo "\033[0;31m" . $msg . "\033[0m" . PHP_EOL;
}

function cliNotice($msg)
{
    echo "\033[0;33m" . $msg . "\033[0m" . PHP_EOL;
}

function cliSuccess($msg)
{
    echo "\033[0;32m" . $msg . "\033[0m" . PHP_EOL;
}
