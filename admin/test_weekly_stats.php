<?php
/**
 * Script de prueba para verificar las estadísticas semanales
 */

session_start();

// Verificar si está logueado
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: login.php');
    exit();
}

// Función para calcular fechas de la semana
function calcularFechasSemana() {
    $hoy = new DateTime();
    $lunes = clone $hoy;
    
    // Obtener el lunes de la semana actual
    $dia_semana = $hoy->format('N'); // 1 = lunes, 7 = domingo
    if ($dia_semana == 1) {
        // Si hoy es lunes, usar hoy como lunes
        $lunes->setTime(0, 0, 0);
    } else {
        // Ir al lunes anterior
        $lunes->modify('last monday');
        $lunes->setTime(0, 0, 0);
    }
    
    // Establecer hoy al final del día
    $hoy->setTime(23, 59, 59);
    
    return [
        'lunes' => $lunes,
        'hoy' => $hoy,
        'dia_semana' => $dia_semana
    ];
}

// Función para procesar registros CSV (simplificada)
function procesarRegistrosPrueba() {
    $registros_file = '../data/registros.csv';
    $stats = [
        'total_descargas' => 0,
        'total_aperturas' => 0,
        'total_visitas' => 0,
        'descargas_semana' => 0,
        'aperturas_semana' => 0,
        'visitas_semana' => 0,
        'registros_semana' => []
    ];
    
    if (!file_exists($registros_file)) {
        return $stats;
    }
    
    $fechas = calcularFechasSemana();
    $lunes = $fechas['lunes'];
    $hoy = $fechas['hoy'];
    
    $handle = fopen($registros_file, 'r');
    $header = fgetcsv($handle); // Saltar encabezado
    
    while (($data = fgetcsv($handle, 1000, ",")) !== FALSE) {
        if (count($data) >= 3) {
            $archivo = $data[0];
            $accion = $data[1];
            $fecha_str = $data[2];
            
            // Contar totales
            if ($accion === 'descarga') {
                $stats['total_descargas']++;
            } elseif ($accion === 'apertura') {
                $stats['total_aperturas']++;
            } elseif ($accion === 'visita') {
                $stats['total_visitas']++;
            }
            
            // Contar semana actual
            try {
                $fecha_registro = new DateTime($fecha_str);
                $fecha_registro->setTime(0, 0, 0);
                
                if ($fecha_registro >= $lunes && $fecha_registro <= $hoy) {
                    $stats['registros_semana'][] = [
                        'archivo' => $archivo,
                        'accion' => $accion,
                        'fecha' => $fecha_str
                    ];
                    
                    if ($accion === 'descarga') {
                        $stats['descargas_semana']++;
                    } elseif ($accion === 'apertura') {
                        $stats['aperturas_semana']++;
                    } elseif ($accion === 'visita') {
                        $stats['visitas_semana']++;
                    }
                }
            } catch (Exception $e) {
                // Ignorar fechas mal formateadas
                continue;
            }
        }
    }
    
    fclose($handle);
    return $stats;
}

$fechas = calcularFechasSemana();
$stats = procesarRegistrosPrueba();
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prueba de Estadísticas Semanales</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #f8f9fa; padding: 2rem 0; }
        .card { margin-bottom: 2rem; }
        .stat-number { font-size: 2rem; font-weight: bold; }
        .text-success { color: #28a745 !important; }
        .text-info { color: #17a2b8 !important; }
        .text-warning { color: #ffc107 !important; }
        .text-danger { color: #dc3545 !important; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="mb-4">Prueba de Estadísticas Semanales</h1>
        
        <!-- Información de fechas -->
        <div class="card">
            <div class="card-header">
                <h3>Información de Fechas</h3>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-4">
                        <strong>Hoy:</strong> <?php echo $fechas['hoy']->format('Y-m-d H:i:s'); ?><br>
                        <strong>Día de la semana:</strong> <?php echo $fechas['dia_semana']; ?> (<?php echo $fechas['dia_semana'] == 1 ? 'Lunes' : ($fechas['dia_semana'] == 2 ? 'Martes' : ($fechas['dia_semana'] == 3 ? 'Miércoles' : ($fechas['dia_semana'] == 4 ? 'Jueves' : ($fechas['dia_semana'] == 5 ? 'Viernes' : ($fechas['dia_semana'] == 6 ? 'Sábado' : 'Domingo'))))); ?>)
                    </div>
                    <div class="col-md-4">
                        <strong>Lunes de la semana:</strong> <?php echo $fechas['lunes']->format('Y-m-d H:i:s'); ?>
                    </div>
                    <div class="col-md-4">
                        <strong>Rango de la semana:</strong><br>
                        Desde: <?php echo $fechas['lunes']->format('Y-m-d'); ?><br>
                        Hasta: <?php echo $fechas['hoy']->format('Y-m-d'); ?>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Estadísticas totales -->
        <div class="row">
            <div class="col-md-4">
                <div class="card text-center">
                    <div class="card-body">
                        <h5 class="card-title text-success">Total Descargas</h5>
                        <div class="stat-number text-success"><?php echo $stats['total_descargas']; ?></div>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card text-center">
                    <div class="card-body">
                        <h5 class="card-title text-info">Total Aperturas</h5>
                        <div class="stat-number text-info"><?php echo $stats['total_aperturas']; ?></div>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card text-center">
                    <div class="card-body">
                        <h5 class="card-title text-warning">Total Visitas</h5>
                        <div class="stat-number text-warning"><?php echo $stats['total_visitas']; ?></div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Estadísticas semanales -->
        <div class="row">
            <div class="col-md-4">
                <div class="card text-center">
                    <div class="card-body">
                        <h5 class="card-title text-success">Descargas Esta Semana</h5>
                        <div class="stat-number text-success"><?php echo $stats['descargas_semana']; ?></div>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card text-center">
                    <div class="card-body">
                        <h5 class="card-title text-info">Aperturas Esta Semana</h5>
                        <div class="stat-number text-info"><?php echo $stats['aperturas_semana']; ?></div>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card text-center">
                    <div class="card-body">
                        <h5 class="card-title text-warning">Visitas Esta Semana</h5>
                        <div class="stat-number text-warning"><?php echo $stats['visitas_semana']; ?></div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Registros de la semana -->
        <div class="card">
            <div class="card-header">
                <h3>Registros de Esta Semana (<?php echo count($stats['registros_semana']); ?> registros)</h3>
            </div>
            <div class="card-body">
                <?php if (empty($stats['registros_semana'])): ?>
                    <p class="text-muted">No hay registros para esta semana.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-sm">
                            <thead>
                                <tr>
                                    <th>Archivo</th>
                                    <th>Acción</th>
                                    <th>Fecha</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($stats['registros_semana'] as $registro): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($registro['archivo']); ?></td>
                                        <td>
                                            <span class="badge bg-<?php echo $registro['accion'] === 'descarga' ? 'success' : ($registro['accion'] === 'apertura' ? 'info' : 'warning'); ?>">
                                                <?php echo $registro['accion']; ?>
                                            </span>
                                        </td>
                                        <td><?php echo $registro['fecha']; ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        
        <div class="text-center mt-4">
            <a href="dashboard.php" class="btn btn-primary">Volver al Dashboard</a>
        </div>
    </div>
</body>
</html>