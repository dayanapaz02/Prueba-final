<?php
/**
 * Script para leer archivos desde el CSV de registro y mostrarlos por categoría
 */

// Configuración de headers
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-cache, must-revalidate');
header('Expires: Sat, 26 Jul 1997 05:00:00 GMT');

// Función para leer archivos desde CSV
function leerArchivosPorCategoria($categoria) {
    $archivos_csv = __DIR__ . '/../data/archivos_registro.csv';
    $archivos = [];
    
    if (!file_exists($archivos_csv)) {
        return $archivos;
    }
    
    $handle = fopen($archivos_csv, 'r');
    if ($handle === false) {
        return $archivos;
    }
    
    // Saltar encabezado
    $header = fgetcsv($handle);
    
    while (($data = fgetcsv($handle)) !== FALSE) {
        if (count($data) >= 8 && $data[5] === $categoria) {
            $archivos[] = [
                'id' => $data[0],
                'nombre_archivo' => $data[1],
                'archivo_original' => $data[2],
                'autor' => $data[3],
                'año' => $data[4],
                'destino' => $data[5],
                'fecha_subida' => $data[6],
                'tamaño' => $data[7]
            ];
        }
    }
    
    fclose($handle);
    
    // Ordenar por fecha de subida (más recientes primero)
    usort($archivos, function($a, $b) {
        return strtotime($b['fecha_subida']) - strtotime($a['fecha_subida']);
    });
    
    return $archivos;
}

// Función para obtener todos los archivos
function leerTodosLosArchivos() {
    $archivos_csv = __DIR__ . '/../data/archivos_registro.csv';
    $archivos = [];
    
    if (!file_exists($archivos_csv)) {
        return $archivos;
    }
    
    $handle = fopen($archivos_csv, 'r');
    if ($handle === false) {
        return $archivos;
    }
    
    // Saltar encabezado
    $header = fgetcsv($handle);
    
    while (($data = fgetcsv($handle)) !== FALSE) {
        if (count($data) >= 8) {
            $archivos[] = [
                'id' => $data[0],
                'nombre_archivo' => $data[1],
                'archivo_original' => $data[2],
                'autor' => $data[3],
                'año' => $data[4],
                'destino' => $data[5],
                'fecha_subida' => $data[6],
                'tamaño' => $data[7]
            ];
        }
    }
    
    fclose($handle);
    
    // Ordenar por fecha de subida (más recientes primero)
    usort($archivos, function($a, $b) {
        return strtotime($b['fecha_subida']) - strtotime($a['fecha_subida']);
    });
    
    return $archivos;
}

// Procesar la petición
$categoria = $_GET['categoria'] ?? '';
$formato = $_GET['formato'] ?? 'json';

if ($categoria) {
    $archivos = leerArchivosPorCategoria($categoria);
} else {
    $archivos = leerTodosLosArchivos();
}

if ($formato === 'html') {
    // Retornar HTML para mostrar archivos
    if (!empty($archivos)) {
        echo '<div class="archivos-container">';
        foreach ($archivos as $archivo) {
            $fecha_formateada = date('d/m/Y', strtotime($archivo['fecha_subida']));
            $tamBytes = isset($archivo['tamaño']) && is_numeric($archivo['tamaño']) ? (float)$archivo['tamaño'] : 0;
            $tamaño_formateado = number_format($tamBytes / 1024, 1);

            $nombre_archivo = htmlspecialchars($archivo['nombre_archivo']);
            $titulo = htmlspecialchars($archivo['archivo_original']);
            $autor = htmlspecialchars($archivo['autor']);
            $anio = htmlspecialchars($archivo['año']);

            echo '<div class="seminario-card" onclick="verArchivo(\'' . $nombre_archivo . '\')" data-archivo="' . $nombre_archivo . '">';
            echo '  <div class="seminario-image">';
            echo '    <img src="Imagenes/3.png" alt="Documento">';
            echo '    <div class="seminario-overlay">';
            echo '      <i class="fas fa-eye"></i>';
            echo '      <span>Ver Documento</span>';
            echo '    </div>';
            echo '  </div>';
            echo '  <div class="seminario-info">';
            echo '    <h3>' . $titulo . '</h3>';
            echo '    <p>' . $autor . ' · ' . $anio . '</p>';
            echo '    <div class="seminario-meta">';
            echo '      <span class="seminario-count">' . $tamaño_formateado . ' KB</span>';
            echo '    </div>';
            echo '  </div>';
            echo '</div>';
        }
        echo '</div>';
    }
} else {
    // Retornar JSON
    echo json_encode([
        'status' => 'success',
        'categoria' => $categoria,
        'total' => count($archivos),
        'archivos' => $archivos
    ]);
}
?>