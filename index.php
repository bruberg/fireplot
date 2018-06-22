<?php
$date = date('Y-m-d');
if ($_GET) {
  if ($_GET['date']) {
    if (preg_match ("/^\d\d\d\d\-\d\d\-\d\d$/", $_GET['date'])) {
      $date = $_GET['date'];
    }
  }
}

if (file_exists ("fireplot-64-${date}.png")) {
    $file = "fireplot-64-${date}.png";
}


$prevday = date_create ($date);
date_sub ($prevday, date_interval_create_from_date_string('1 day'));
$prevday_str = date_format ($prevday, 'Y-m-d');

$nextday = date_create ($date);
date_add ($nextday, date_interval_create_from_date_string('1 day'));
$nextday_str = date_format ($nextday, 'Y-m-d');

?><html>
 <head>
  <title>Fireplot</title>
  <link rel="icon" href="fireplot.ico" type="image/x-icon"/>
  <link rel="shortcut icon" href="fireplot.ico" type="image/x-icon"/>
  <style>
    body { background-color: black; color: cyan; }
    h1 { margin: 0px; padding: 0px; }
    div { margin: 0px; padding: 0px; }
  </style>
 </head>
 <body>
  <h1>Firewall plot <?php print $date; ?></h1>
  <div>
    <a href="?date=<?php print date('Y-m-d'); ?>">today</a> |
    <a href="?date=<?php print $prevday_str; ?>">previous day</a> |
    <a href="?date=<?php print $nextday_str; ?>">next day</a>
  </div>
  <div>
<?php if (file_exists ("imagemap-${date}.map")) { ?>
    <img src="<?php print $file; ?>" usemap="#fireplot-<?php print $date; ?>" />
    <map name="fireplot-<?php print $date; ?>">
<?php include ("imagemap-${date}.map"); ?>
    </map>
<?php } else { ?>
    <img src="<?php print $file; ?>" />
<?php } ?>
  </div>
 </body>
</html>

