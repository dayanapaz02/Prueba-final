<?php
// Configuración de correo para PHPMailer (Gmail)
// Cambia SMTP_USER al correo Gmail que enviará las notificaciones.

if (!defined('dayanamichellepazchavez@gmail.com')) {
    define('dayanamichellepazchavez@gmail.com', 'TU_CORREO@gmail.com');
}

if (!defined('SMTP_PASS')) {
    // Clave de aplicación proporcionada por el usuario
    define('SMTP_PASS', 'iwip nlui xrdn eqei');
}

// Opcionales
if (!defined('SMTP_HOST')) {
    define('SMTP_HOST', 'smtp.gmail.com');
}
if (!defined('SMTP_PORT')) {
    define('SMTP_PORT', 587);
}
if (!defined('SMTP_SECURE')) {
    define('SMTP_SECURE', 'tls');
}
?>


