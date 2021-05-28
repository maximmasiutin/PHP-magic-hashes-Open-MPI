#!/usr/bin/php
<?php

require "phpmagic_sha1.php";

$p1 = $arr[0];
$p2 = $arr[1];

$h1 = hash('sha1',$p1,false);
$h2 = hash('sha1',$p2,false);


if ($h1 == $h2)
{
  print "$h1 == $h2".PHP_EOL;
} else
{
  print "Not matched".PHP_EOL;
}
?>