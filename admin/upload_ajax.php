<?php
session_start();
header('Content-Type: application/json');

if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'No autorizado']);
    exit;
}

$archivos_csv = __DIR__ . '/../data/archivos_registro.csv';
$data_dir = __DIR__ . '/../data/';

if (!is_dir($data_dir)) {
    mkdir($data_dir, 0755, true);
}
if (!file_exists($archivos_csv)) {
    $handle = fopen($archivos_csv, 'w');
    fputcsv($handle, ['id', 'nombre_archivo', 'archivo_original', 'autor', 'año', 'destino', 'fecha_subida', 'tamaño']);
    fclose($handle);
}

$destino = $_POST['destino'] ?? '';
$autor = trim($_POST['autor'] ?? '');
$anio = trim($_POST['año'] ?? ($_POST['anio'] ?? ''));

if (!isset($_FILES['archivo']) || $_FILES['archivo']['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Archivo inválido']);
    exit;
}

if (empty($autor) || empty($anio) || !in_array($destino, ['simposios','seminarios','cursos'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Datos incompletos']);
    exit;
}

$archivo_info = $_FILES['archivo'];
$nombre_original = $archivo_info['name'];
$ext = strtolower(pathinfo($nombre_original, PATHINFO_EXTENSION));
if (!in_array($ext, ['pdf','doc','docx'])) {
    http_response_code(415);
    echo json_encode(['success' => false, 'message' => 'Formato no permitido']);
    exit;
}

$nombre_archivo = uniqid() . '_' . preg_replace('/[^a-zA-Z0-9._-]/', '', $nombre_original);
$ruta_destino = __DIR__ . '/../uploads/' . $destino . '/';
if (!is_dir($ruta_destino)) {
    mkdir($ruta_destino, 0755, true);
}
$ruta_completa = $ruta_destino . $nombre_archivo;

if (!move_uploaded_file($archivo_info['tmp_name'], $ruta_completa)) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'No se pudo guardar el archivo']);
    exit;
}

$handle = fopen($archivos_csv, 'a');
$id = time();
$fecha = date('Y-m-d H:i:s');
$tam = filesize($ruta_completa);
fputcsv($handle, [$id, $nombre_archivo, $nombre_original, $autor, $anio, $destino, $fecha, $tam]);
fclose($handle);

// Enviar notificaciones
require_once __DIR__ . '/../scripts/send_notifications.php';
$notif = enviarNotificacionesArchivo($nombre_original, $destino);

echo json_encode([
    'success' => true,
    'message' => 'Archivo subido',
    'file' => $nombre_archivo,
    'destino' => $destino,
    'notifications' => $notif
]);
?>


