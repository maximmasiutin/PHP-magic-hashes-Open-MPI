#!/usr/bin/php
<?php

require "phpmagic_sha1.php";

foreach ($arr as &$value) {
$sha1 = hash('sha1',$value,false);
if ($sha1 == '0')
{
  print $value."\t".$sha1.PHP_EOL;
} else
{
  print "Not matched".PHP_EOL;
}
}
?>