<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require __DIR__ . '/../admin/PHPMailer/src/Exception.php';
require __DIR__ . '/../admin/PHPMailer/src/PHPMailer.php';
require __DIR__ . '/../admin/PHPMailer/src/SMTP.php';
require __DIR__ . '/../admin/mail_config.php';

/**
 * Enviar notificaciones por correo a usuarios registrados
 * @param string $fileName Nombre del archivo subido
 * @param string $destino  Categoria destino (simposios|seminarios|cursos)
 * @return array Resultado
 */
function enviarNotificacionesArchivo($fileName, $destino) {
    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host = SMTP_HOST;
        $mail->SMTPAuth = true;
        $mail->Username = SMTP_USER;
        $mail->Password = SMTP_PASS; // clave de app
        $mail->SMTPSecure = SMTP_SECURE;
        $mail->Port = SMTP_PORT;

        $mail->setFrom(SMTP_USER, 'Biblioteca Virtual IHCAFÉ');
        $mail->isHTML(true);

        $categoriaLabel = ucfirst($destino);
        $asunto = 'Nuevo archivo disponible - ' . $categoriaLabel;
        $mensaje = '<html><body>'
            . '<h3>Nuevo archivo disponible</h3>'
            . '<p>Se ha subido el archivo: <strong>' . htmlspecialchars($fileName) . '</strong></p>'
            . '<p>Categoría: <strong>' . htmlspecialchars($categoriaLabel) . '</strong></p>'
            . '<p><a href="' . obtenerURLBase() . '">Ir a la biblioteca</a></p>'
            . '<hr><p style="font-size:12px;color:gray;">Este es un mensaje automático.</p>'
            . '</body></html>';
        $mail->Subject = $asunto;
        $mail->Body = $mensaje;

        // Leer correos desde data/usuarios.csv (si existe)
        $archivoUsuarios = __DIR__ . '/../data/usuarios.csv';
        if (file_exists($archivoUsuarios)) {
            if (($handle = fopen($archivoUsuarios, 'r')) !== false) {
                // Saltar encabezado si parece encabezado
                $first = fgetcsv($handle);
                if ($first && filter_var($first[1] ?? '', FILTER_VALIDATE_EMAIL)) {
                    // Primera fila ya era correo válido, incluirla
                    $mail->addAddress(trim($first[1]));
                }
                while (($row = fgetcsv($handle)) !== false) {
                    $correo = trim($row[1] ?? '');
                    if (filter_var($correo, FILTER_VALIDATE_EMAIL)) {
                        $mail->addAddress($correo);
                    }
                }
                fclose($handle);
            }
        }

        if (count($mail->getToAddresses()) === 0) {
            // No hay destinatarios; retornar sin error
            return ['success' => true, 'message' => 'Sin destinatarios'];
        }

        $mail->send();
        return ['success' => true, 'message' => 'Notificaciones enviadas'];
    } catch (Exception $e) {
        return ['success' => false, 'message' => $mail->ErrorInfo];
    }
}

function obtenerURLBase() {
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $path = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/'), '/\\');
    return $protocol . $host . ($path ? $path . '/' : '/');
}
?>


