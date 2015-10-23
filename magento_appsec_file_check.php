<?php

// PATH TO MAGENTO ROOT
//
$_magentoPath='/home/www/magento/';

if (!file_exists($_magentoPath. 'app/Mage.php')) {
	echo 'Magento not found!'. "\n";
	exit;
}

// SECURITY NOTICES AND QUERIES
//
$_securityNotices=array(
	'APPSEC-1034' => array(
		'text' => 'addressing bypassing custom admin URL',
		'exec' => array(
			'path' => array(
					$_magentoPath. 'app/code/*'
				),
			'cmd' => 'grep -irl ' ,
			'query' => array(
				'"<use>admin</use>"'
				)
		),
		'magentopath' => $_magentoPath),
	'APPSEC-1063' => array(
		'text' => 'addressing possible SQL injection',
		'exec' => array(
			'path' => array(
					$_magentoPath. 'app/code/community/*',
					$_magentoPath. 'app/code/local/*'
				),
			'cmd' => 'grep -irl ' ,
			'query' => array(
				'"collection->addFieldToFilter(\'"',
				'"collection->addFieldToFilter(\'\`"',
			)
		),
		'magentopath' => $_magentoPath),
	'APPSEC-1057' => array(
		'text' => 'template processing method allows access to private information',
		'exec' => array(
			'path' => array(
					$_magentoPath. 'app/code/community/*',
					$_magentoPath. 'app/code/local/*',
					$_magentoPath. 'app/locale/*',
					$_magentoPath. 'app/design/frontend/*'
				),
			'cmd' => 'grep -irl ' ,
			'query' => array(
				'"{{config path="',
				'"{{block type="',
			)
		),
		'magentopath' => $_magentoPath)			
);

// EXEC
//
echo '*** Magento security file check ***'. "\n";
$_count=1;

foreach ($_securityNotices as $_name => $_securityNotice)
{

	echo '['. $_count++. '] '. $_name. ', '. $_securityNotice['text']. "\n";
	echo doExec($_securityNotice,$_name)."\n\n";

}

echo '***********************************'. "\n";
exit;


function doExec($_securityNotice,$_name)
{
	$_text='';	
	$_exec=$_securityNotice['exec']['cmd'];	
	
	foreach ($_securityNotice['exec']['path'] as $_searchPath)
	{
		$_text=$_text.'looking in '. $_searchPath. "\n";			
		
		$_count=0;
		$_search='';
			
		foreach ($_securityNotice['exec']['query'] as $_searchQuery)
		{

			exec($_exec. $_searchQuery. ' '. $_searchPath, $_output, $_status);
			
			if (1 === $_status)
			{
				
				$_text=$_text.$_searchQuery. ' not found.'. "\n";
				continue;
			}

			if (0 === $_status)
			{
				$_count=$_count + count($_output);
				
				foreach ($_output as $_line)
				{
					$_search=$_search.'['. $_name. '] '. $_searchQuery. ' found in '. "\033[31m". str_replace($_securityNotice['magentopath'],' ', $_line). "\033[0m\n";
				}
				
			} else {
				$_text=$_text. 'Command '. $_securityNotice['exec']['cmd']. ' failed with status: ' . $_status. "\n";
			}
			
		}
		
		$_text=$_text.$_count. ' affected files : '. "\n". $_search. "\n";
	}
	
	return $_text;
	
}
