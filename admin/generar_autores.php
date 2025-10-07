<?php
/**
 * Script para generar archivo autores.js desde el CSV de archivos registrados
 */

session_start();

// Verificar si está logueado
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: login.php');
    exit();
}

$archivos_csv = '../data/archivos_registro.csv';
$autores_js = '../autores.js';

if (file_exists($archivos_csv)) {
    $autores = [];
    
    $handle = fopen($archivos_csv, 'r');
    $header = fgetcsv($handle); // Saltar encabezado
    
    while (($data = fgetcsv($handle)) !== FALSE) {
        if (count($data) >= 8) {
            $archivo_original = $data[2]; // archivo_original
            $autor = $data[3]; // autor
            
            $autores[$archivo_original] = $autor;
        }
    }
    fclose($handle);
    
    // Generar archivo JavaScript
    $js_content = "// Archivo generado automáticamente desde el sistema de gestión\n";
    $js_content .= "// No editar manualmente\n\n";
    $js_content .= "window.autoresData = {\n";
    
    $first = true;
    foreach ($autores as $archivo => $autor) {
        if (!$first) $js_content .= ",\n";
        $js_content .= "    \"" . addslashes($archivo) . "\": \"" . addslashes($autor) . "\"";
        $first = false;
    }
    
    $js_content .= "\n};\n\n";
    $js_content .= "function getAutorFromGlobal(fileName) {\n";
    $js_content .= "    return window.autoresData[fileName] || 'IHCAFÉ';\n";
    $js_content .= "}\n";
    
    file_put_contents($autores_js, $js_content);
    
    echo json_encode([
        'status' => 'success',
        'message' => 'Archivo autores.js generado correctamente',
        'archivos_procesados' => count($autores)
    ]);
} else {
    echo json_encode([
        'status' => 'error',
        'message' => 'No se encontró el archivo de registro'
    ]);
}
?>