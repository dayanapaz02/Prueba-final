<?php
/**
 * Script para registrar eventos de descarga y apertura
 * Recibe parámetros: archivo y accion
 * Guarda en data/registros.csv
 */

// Configuración
$registros_file = '../data/registros.csv';
$data_dir = '../data/';

// Verificar que el directorio data existe
if (!is_dir($data_dir)) {
    mkdir($data_dir, 0755, true);
}

// Obtener parámetros
$archivo = trim($_GET['archivo'] ?? $_POST['archivo'] ?? '');
$accion = trim($_GET['accion'] ?? $_POST['accion'] ?? '');

// Validar parámetros
if (empty($archivo) || empty($accion)) {
    http_response_code(400);
    echo json_encode([
        'error' => 'Parámetros requeridos: archivo y accion',
        'status' => 'error'
    ]);
    exit();
}

// Validar acción
if (!in_array($accion, ['descarga', 'apertura'])) {
    http_response_code(400);
    echo json_encode([
        'error' => 'Acción debe ser "descarga" o "apertura"',
        'status' => 'error'
    ]);
    exit();
}

// Sanitizar nombre de archivo
$archivo = basename($archivo); // Remover path traversal
$archivo = preg_replace('/[^a-zA-Z0-9._-]/', '', $archivo); // Solo caracteres seguros

// Fecha actual
$fecha = date('Y-m-d H:i:s');

// Crear línea CSV
$linea = [
    $archivo,
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
        'message' => 'Evento registrado correctamente',
        'status' => 'success',
        'data' => [
            'archivo' => $archivo,
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



