<?php
/**
 * Script para registrar visitas REALES a páginas HTML
 * - Filtra bots/crawlers por User-Agent
 * - Evita duplicados por sesión para la misma página por ventana de tiempo
 */

header('Content-Type: application/json');

// Iniciar sesión para de-duplicación por sesión
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Configuración
$registros_file = '../data/registros.csv';
$data_dir = '../data/';

// Ventana de de-duplicación por página (segundos)
$DEDUP_WINDOW_SECONDS = 1800; // 30 minutos

// Verificar que el directorio data existe
if (!is_dir($data_dir)) {
    mkdir($data_dir, 0755, true);
}

// Obtener parámetros
$pagina = trim($_POST['pagina'] ?? $_GET['pagina'] ?? '');
$accion = 'visita'; // Siempre es una visita para este script

// Validar parámetros
if (empty($pagina)) {
    http_response_code(400);
    echo json_encode([
        'error' => 'Parámetro requerido: pagina',
        'status' => 'error'
    ]);
    exit();
}

// Sanitizar nombre de página
$pagina = basename($pagina); // Solo el nombre del archivo
$pagina = preg_replace('/[^a-zA-Z0-9._-]/', '', $pagina); // Solo caracteres seguros

// Filtrado básico de bots por User-Agent
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$ua = strtolower($userAgent);
$botPatterns = [
    'bot', 'spider', 'crawl', 'slurp', 'bingpreview', 'mediapartners-google',
    'crawler', 'curl', 'wget', 'python-requests', 'httpclient', 'libwww',
    'facebookexternalhit', 'embedly', 'quora link preview', 'discordbot',
    'linkedinbot', 'slackbot', 'twitterbot', 'telegrambot', 'whatsapp',
    'preview', 'headless', 'phantom', 'puppeteer', 'chrome-lighthouse'
];
foreach ($botPatterns as $pattern) {
    if (strpos($ua, $pattern) !== false) {
        echo json_encode(['status' => 'ignored', 'reason' => 'bot_detected']);
        exit();
    }
}

// De-duplicación por sesión para la misma página
if (!isset($_SESSION['visited_pages'])) {
    $_SESSION['visited_pages'] = [];
}

$now = time();
$lastVisitTs = $_SESSION['visited_pages'][$pagina] ?? 0;
if ($lastVisitTs && ($now - $lastVisitTs) < $DEDUP_WINDOW_SECONDS) {
    echo json_encode([
        'status' => 'ignored',
        'reason' => 'deduplicated',
        'window_seconds' => $DEDUP_WINDOW_SECONDS
    ]);
    exit();
}

// Registrar nueva visita y actualizar de-dup
$_SESSION['visited_pages'][$pagina] = $now;

// Fecha actual
$fecha = date('Y-m-d H:i:s');

// Crear línea CSV
$linea = [
    $pagina,
    $accion,
    $fecha
];

// Bloquear archivo para escritura concurrente
$handle = fopen($registros_file, 'a');
if ($handle === false) {
    http_response_code(500);
    echo json_encode([
        'error' => 'No se pudo abrir el archivo de registros',
        'status' => 'error'
    ]);
    exit();
}

// Intentar bloquear el archivo
if (flock($handle, LOCK_EX)) {
    // Verificar si el archivo necesita encabezado
    if (filesize($registros_file) == 0) {
        // Escribir encabezado si el archivo está vacío
        fputcsv($handle, ['nombre_archivo', 'accion', 'fecha']);
    }
    
    // Escribir el registro
    fputcsv($handle, $linea);
    
    // Liberar el bloqueo
    flock($handle, LOCK_UN);
    
    // Cerrar archivo
    fclose($handle);
    
    // Respuesta exitosa
    echo json_encode([
        'message' => 'Visita registrada correctamente',
        'status' => 'success',
        'data' => [
            'pagina' => $pagina,
            'accion' => $accion,
            'fecha' => $fecha
        ]
    ]);
    
} else {
    // No se pudo bloquear el archivo
    fclose($handle);
    http_response_code(500);
    echo json_encode([
        'error' => 'No se pudo bloquear el archivo para escritura',
        'status' => 'error'
    ]);
}
?>
