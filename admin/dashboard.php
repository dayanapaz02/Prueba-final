<?php
session_start();

// Verificar si está logueado
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: login.php');
    exit();
}

// Función para procesar registros CSV
function procesarRegistros() {
    $registros_file = '../data/registros.csv';
    $stats = [
        'total_descargas' => 0,
        'total_aperturas' => 0,
        'total_visitas' => 0,
        'descargas_semana' => 0,
        'aperturas_semana' => 0,
        'visitas_semana' => 0,
        'archivos_populares' => [],
        'paginas_populares' => []
    ];
    
    if (!file_exists($registros_file)) {
        return $stats;
    }
    
    // Calcular fechas de la semana actual (lunes a hoy)
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
    
    $handle = fopen($registros_file, 'r');
    
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
                // Solo contamos visitas reales a index.html
                if ($archivo === 'index.html') {
                    $stats['total_visitas']++;
                }
            }
            
            // Contar semana actual (desde lunes hasta hoy)
            try {
                $fecha_registro = new DateTime($fecha_str);
                $fecha_registro->setTime(0, 0, 0);
                
                // Verificar si está en la semana actual (lunes a hoy)
                if ($fecha_registro >= $lunes && $fecha_registro <= $hoy) {
                    if ($accion === 'descarga') {
                        $stats['descargas_semana']++;
                    } elseif ($accion === 'apertura') {
                        $stats['aperturas_semana']++;
                    } elseif ($accion === 'visita') {
                        // Solo contamos visitas a index.html en la semana
                        if ($archivo === 'index.html') {
                            $stats['visitas_semana']++;
                        }
                    }
                }
            } catch (Exception $e) {
                // Ignorar fechas mal formateadas
                continue;
            }
            
            // Contar archivos populares (solo descargas)
            if ($accion === 'descarga') {
                if (!isset($stats['archivos_populares'][$archivo])) {
                    $stats['archivos_populares'][$archivo] = 0;
                }
                $stats['archivos_populares'][$archivo]++;
            }
            
            // Contar páginas populares (solo visitas)
            if ($accion === 'visita') {
                if (!isset($stats['paginas_populares'][$archivo])) {
                    $stats['paginas_populares'][$archivo] = 0;
                }
                $stats['paginas_populares'][$archivo]++;
            }
        }
    }
    
    fclose($handle);
    
    // Ordenar archivos y páginas populares
    arsort($stats['archivos_populares']);
    $stats['archivos_populares'] = array_slice($stats['archivos_populares'], 0, 10, true);
    
    arsort($stats['paginas_populares']);
    $stats['paginas_populares'] = array_slice($stats['paginas_populares'], 0, 10, true);
    
    return $stats;
}

$stats = procesarRegistros();

// Manejar logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: login.php');
    exit();
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Panel Administración Biblioteca virtual - IHCAFE</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f5f6fa;
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        /* Sidebar */
        .sidebar {
            position: fixed;
            top: 0;
            left: 0;
            width: 280px;
            height: 100vh;
            background: linear-gradient(180deg, #2c3e50 0%, #34495e 100%);
            z-index: 1000;
            overflow-y: auto;
            transition: all 0.3s ease;
        }
        
        .sidebar-header {
            padding: 2rem 1.5rem;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            text-align: center;
        }
        
        .user-avatar {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            background: rgba(255,255,255,0.1);
            margin: 0 auto 1rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2rem;
            color: white;
        }
        
        .user-name {
            color: white;
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        
        .user-email {
            color: #bdc3c7;
            font-size: 0.9rem;
        }
        
        .sidebar-nav {
            padding: 1rem 0;
        }
        
        .nav-item {
            margin: 0.5rem 0;
        }
        
        .nav-link {
            display: flex;
            align-items: center;
            padding: 1rem 1.5rem;
            color: #ecf0f1;
            text-decoration: none;
            transition: all 0.3s ease;
            border-left: 3px solid transparent;
        }
        
        .nav-link:hover {
            background: rgba(255,255,255,0.1);
            border-left-color: #3498db;
            color: white;
        }
        
        .nav-link.active {
            background: rgba(52, 152, 219, 0.2);
            border-left-color: #3498db;
            color: #3498db;
        }
        
        .nav-icon {
            width: 20px;
            height: 20px;
            margin-right: 1rem;
            font-size: 1.1rem;
        }
        
        /* Main Content */
        .main-content {
            margin-left: 280px;
            min-height: 100vh;
            background: #f5f6fa;
        }
        
        .top-bar {
            background: white;
            padding: 1rem 2rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .page-title {
            font-size: 2rem;
            font-weight: 700;
            color: #2c3e50;
            margin: 0;
        }
        
        .hamburger-menu {
            width: 30px;
            height: 30px;
            cursor: pointer;
            display: flex;
            flex-direction: column;
            justify-content: space-around;
        }
        
        .hamburger-line {
            width: 100%;
            height: 3px;
            background: #2c3e50;
            border-radius: 2px;
        }
        
        .content-area {
            padding: 2rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: white;
            border-radius: 15px;
            padding: 1.5rem;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 40px rgba(0,0,0,0.15);
        }
        
        .stat-card.primary {
            background: linear-gradient(135deg, #3498db, #2980b9);
            color: white;
        }
        
        .stat-card.success {
            background: linear-gradient(135deg, #27ae60, #229954);
            color: white;
        }
        
        .stat-card.warning {
            background: linear-gradient(135deg, #f39c12, #e67e22);
            color: white;
        }
        
        .stat-card.danger {
            background: linear-gradient(135deg, #e74c3c, #c0392b);
            color: white;
        }
        
        .stat-card.info {
            background: linear-gradient(135deg, #17a2b8, #138496);
            color: white;
        }
        
        .stat-card.purple {
            background: linear-gradient(135deg, #8e44ad, #732d91);
            color: white;
        }
        
        .stat-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }
        
        .stat-title {
            font-size: 0.9rem;
            font-weight: 600;
            opacity: 0.9;
            margin: 0;
        }
        
        .stat-icon {
            width: 40px;
            height: 40px;
            border-radius: 10px;
            background: rgba(255,255,255,0.2);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            margin: 0;
            line-height: 1;
        }
        
        .stat-subtitle {
            font-size: 0.8rem;
            opacity: 0.8;
            margin-top: 0.5rem;
        }
        
        /* Charts Section */
        .charts-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .chart-card {
            background: white;
            border-radius: 15px;
            padding: 1.5rem;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
        }
        
        .chart-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }
        
        .chart-title {
            font-size: 1.2rem;
            font-weight: 600;
            color: #2c3e50;
            margin: 0;
        }
        
        .check-button {
            background: linear-gradient(135deg, #f39c12, #e67e22);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .check-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(243, 156, 18, 0.3);
        }
        
        /* Tables */
        .tables-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
        }
        
        .table-card {
            background: white;
            border-radius: 15px;
            overflow: hidden;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
        }
        
        .table-header {
            background: #f8f9fa;
            padding: 1.5rem;
            border-bottom: 1px solid #dee2e6;
        }
        
        .table-title {
            font-size: 1.1rem;
            font-weight: 600;
            color: #2c3e50;
            margin: 0;
            display: flex;
            align-items: center;
        }
        
        .table-title i {
            margin-right: 0.5rem;
            color: #3498db;
        }
        
        .table-responsive {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .table {
            margin: 0;
        }
        
        .table th {
            background: #f8f9fa;
            border: none;
            font-weight: 600;
            color: #495057;
            padding: 1rem;
        }
        
        .table td {
            border: none;
            padding: 1rem;
            vertical-align: middle;
        }
        
        .table tbody tr:hover {
            background-color: #f8f9fa;
        }
        
        .badge-rank {
            background: linear-gradient(135deg, #f39c12, #e67e22);
            color: white;
            font-weight: 600;
            padding: 0.5rem 0.8rem;
            border-radius: 20px;
            font-size: 0.8rem;
        }
        
        .badge {
            padding: 0.4rem 0.8rem;
            border-radius: 15px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        
        .badge.bg-primary {
            background: linear-gradient(135deg, #3498db, #2980b9) !important;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
            }
            
            .sidebar.show {
                transform: translateX(0);
            }
            
            .main-content {
                margin-left: 0;
            }
            
            .charts-grid {
                grid-template-columns: 1fr;
            }
            
            .tables-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-header">
            <div class="user-avatar">
                <i class="fas fa-user"></i>
            </div>
            <div class="user-name"><?php echo strtoupper(htmlspecialchars($_SESSION['admin_usuario'])); ?></div>
            <div class="user-email">admin@ihcafe.hn</div>
        </div>
        
        <nav class="sidebar-nav">
            <div class="nav-item">
                <a href="#" class="nav-link active">
                    <i class="fas fa-home nav-icon"></i>
                    Dashboard
                </a>
            </div>
            <div class="nav-item">
                <a href="/index.html" class="nav-link">
                    <i class="fas fa-globe nav-icon"></i>
                    Sitio Web
                </a>
            </div>
            <div class="nav-item">
                <a href="reportes.php" class="nav-link">
                    <i class="fas fa-file-alt nav-icon"></i>
                    Subir Archivos 
                </a>
            </div>
            <div class="nav-item">
                <a href="?logout=1" class="nav-link">
                    <i class="fas fa-sign-out-alt nav-icon"></i>
                    Cerrar Sesión
                </a>
            </div>
        </nav>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Bar -->
        <div class="top-bar">
            <h1 class="page-title">Dashboard IHCAFE</h1>
            <div class="hamburger-menu" onclick="toggleSidebar()">
                <div class="hamburger-line"></div>
                <div class="hamburger-line"></div>
                <div class="hamburger-line"></div>
            </div>
        </div>

        <!-- Content Area -->
        <div class="content-area">
            <!-- Stats Grid -->
            <div class="stats-grid">
                <div class="stat-card primary">
                    <div class="stat-header">
                        <p class="stat-title">Total Descargas</p>
                        <div class="stat-icon">
                            <i class="fas fa-download"></i>
                        </div>
                    </div>
                    <h2 class="stat-value"><?php echo number_format($stats['total_descargas']); ?></h2>
                    <p class="stat-subtitle">Todos los archivos descargados</p>
                </div>
                
                <div class="stat-card success">
                    <div class="stat-header">
                        <p class="stat-title">Descargas Esta Semana</p>
                        <div class="stat-icon">
                            <i class="fas fa-calendar-week"></i>
                        </div>
                    </div>
                    <h2 class="stat-value"><?php echo number_format($stats['descargas_semana']); ?></h2>
                    <p class="stat-subtitle">Desde el lunes hasta hoy</p>
                </div>
                
                <div class="stat-card info">
                    <div class="stat-header">
                        <p class="stat-title">Total Aperturas</p>
                        <div class="stat-icon">
                            <i class="fas fa-eye"></i>
                        </div>
                    </div>
                    <h2 class="stat-value"><?php echo number_format($stats['total_aperturas']); ?></h2>
                    <p class="stat-subtitle">Archivos vistos en navegador</p>
                </div>
                
                <div class="stat-card warning">
                    <div class="stat-header">
                        <p class="stat-title">Aperturas Esta Semana</p>
                        <div class="stat-icon">
                            <i class="fas fa-eye"></i>
                        </div>
                    </div>
                    <h2 class="stat-value"><?php echo number_format($stats['aperturas_semana']); ?></h2>
                    <p class="stat-subtitle">Desde el lunes hasta hoy</p>
                </div>
                
                <div class="stat-card purple">
                    <div class="stat-header">
                        <p class="stat-title">Total Visitas</p>
                        <div class="stat-icon">
                            <i class="fas fa-globe"></i>
                        </div>
                    </div>
                    <h2 class="stat-value"><?php echo number_format($stats['total_visitas']); ?></h2>
                    <p class="stat-subtitle">Visitas a páginas HTML</p>
                </div>
                
                <div class="stat-card danger">
                    <div class="stat-header">
                        <p class="stat-title">Visitas Esta Semana</p>
                        <div class="stat-icon">
                            <i class="fas fa-globe"></i>
                        </div>
                    </div>
                    <h2 class="stat-value"><?php echo number_format($stats['visitas_semana']); ?></h2>
                    <p class="stat-subtitle">Desde el lunes hasta hoy</p>
                </div>
            </div>

            <!-- Charts Section -->
            <div class="charts-grid">
                <div class="chart-card">
                    <div class="chart-header">
                        <h3 class="chart-title">Actividad del Sitio</h3>
                        <button class="check-button" onclick="location.reload()">
                            <i class="fas fa-sync-alt"></i> Actualizar
                        </button>
                    </div>
                    <div style="height: 300px; background: linear-gradient(135deg, #f8f9fa, #e9ecef); border-radius: 10px; display: flex; align-items: center; justify-content: center; color: #6c757d;">
                        <div style="text-align: center;">
                            <i class="fas fa-chart-bar" style="font-size: 3rem; margin-bottom: 1rem;"></i>
                            <p>Gráfico de actividad en desarrollo</p>
                        </div>
                    </div>
                </div>
                
                <div class="chart-card">
                    <div class="chart-header">
                        <h3 class="chart-title">Distribución</h3>
                        <button class="check-button">
                            <i class="fas fa-eye"></i> Ver Detalles
                        </button>
                    </div>
                    <div style="height: 300px; display: flex; flex-direction: column; align-items: center; justify-content: center;">
                        <div style="position: relative; width: 150px; height: 150px;">
                            <div style="width: 150px; height: 150px; border-radius: 50%; background: conic-gradient(#3498db 0deg 162deg, #f39c12 162deg 360deg); display: flex; align-items: center; justify-content: center;">
                                <div style="width: 100px; height: 100px; background: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; font-weight: bold; color: #2c3e50;">
                                    45%
                                </div>
                            </div>
                        </div>
                        <div style="margin-top: 1rem; text-align: center;">
                            <p style="margin: 0.5rem 0; color: #6c757d;">Descargas: 45%</p>
                            <p style="margin: 0.5rem 0; color: #6c757d;">Aperturas: 35%</p>
                            <p style="margin: 0.5rem 0; color: #6c757d;">Visitas: 20%</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Subir Archivo Rápido -->
            <div class="chart-card" style="margin-bottom: 2rem;">
                <div class="chart-header">
                    <h3 class="chart-title"><i class="fas fa-cloud-upload-alt" style="margin-right:8px;color:#27ae60"></i>Subir Archivo Rápido</h3>
                    <button class="check-button" id="btnLimpiarUpload"><i class="fas fa-eraser"></i> Limpiar</button>
                </div>
                <form id="quickUploadForm">
                    <div class="row" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem">
                        <div>
                            <label style="display:block;font-weight:600;margin-bottom:.3rem;color:#2c3e50">Archivo</label>
                            <input type="file" id="quArchivo" name="archivo" accept=".pdf,.doc,.docx" required style="width:100%;padding:.6rem;border:1px solid #dee2e6;border-radius:8px">
                            <small style="color:#6c757d">PDF, DOC o DOCX</small>
                        </div>
                        <div>
                            <label style="display:block;font-weight:600;margin-bottom:.3rem;color:#2c3e50">Destino</label>
                            <select id="quDestino" name="destino" required style="width:100%;padding:.6rem;border:1px solid #dee2e6;border-radius:8px">
                                <option value="">Seleccionar...</option>
                                <option value="simposios">Simposios Latinoamericanos</option>
                                <option value="seminarios">Seminarios</option>
                                <option value="Otras investigaciones">Otras investigaciones</option>
                                <option value="cursos">Cursos Regionales</option>
                            </select>
                        </div>
                        <div>
                            <label style="display:block;font-weight:600;margin-bottom:.3rem;color:#2c3e50">Autor</label>
                            <input type="text" id="quAutor" name="autor" required placeholder="Nombre del autor" style="width:100%;padding:.6rem;border:1px solid #dee2e6;border-radius:8px">
                        </div>
                        <div>
                            <label style="display:block;font-weight:600;margin-bottom:.3rem;color:#2c3e50">Año</label>
                            <input type="text" id="quAnio" name="año" required placeholder="Ej: 2024" style="width:100%;padding:.6rem;border:1px solid #dee2e6;border-radius:8px">
                        </div>
                    </div>
                    <div style="margin-top:1rem;display:flex;gap:.6rem;justify-content:flex-end">
                        <button type="submit" class="check-button" style="background:linear-gradient(135deg,#27ae60,#229954)"><i class="fas fa-upload"></i> Subir</button>
                    </div>
                    <div id="quMsg" style="margin-top:1rem;font-weight:600"></div>
                </form>
            </div>

            <!-- Tables Section -->
            <div class="tables-grid">
                <div class="table-card">
                    <div class="table-header">
                        <h3 class="table-title">
                            <i class="fas fa-trophy"></i>
                            Top Archivos Descargados
                        </h3>
                    </div>
                    <div class="table-responsive">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th width="60">#</th>
                                    <th>Archivo</th>
                                    <th width="100">Descargas</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (empty($stats['archivos_populares'])): ?>
                                    <tr>
                                        <td colspan="3" style="text-align: center; padding: 2rem; color: #6c757d;">
                                            <i class="fas fa-inbox" style="font-size: 2rem; margin-bottom: 1rem; display: block;"></i>
                                            No hay registros de descargas aún
                                        </td>
                                    </tr>
                                <?php else: ?>
                                    <?php $rank = 1; foreach (array_slice($stats['archivos_populares'], 0, 5, true) as $archivo => $cantidad): ?>
                                        <tr>
                                            <td>
                                                <?php if ($rank <= 3): ?>
                                                    <span class="badge-rank"><?php echo $rank; ?></span>
                                                <?php else: ?>
                                                    <span class="badge bg-secondary"><?php echo $rank; ?></span>
                                                <?php endif; ?>
                                            </td>
                                            <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;">
                                                <i class="fas fa-file-pdf" style="color: #e74c3c; margin-right: 0.5rem;"></i>
                                                <?php echo htmlspecialchars(substr($archivo, 0, 30)) . (strlen($archivo) > 30 ? '...' : ''); ?>
                                            </td>
                                            <td>
                                                <span class="badge bg-primary"><?php echo number_format($cantidad); ?></span>
                                            </td>
                                        </tr>
                                        <?php $rank++; ?>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div class="table-card">
                    <div class="table-header">
                        <h3 class="table-title">
                            <i class="fas fa-globe"></i>
                            Top Páginas Visitadas
                        </h3>
                    </div>
                    <div class="table-responsive">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th width="60">#</th>
                                    <th>Página</th>
                                    <th width="100">Visitas</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (empty($stats['paginas_populares'])): ?>
                                    <tr>
                                        <td colspan="3" style="text-align: center; padding: 2rem; color: #6c757d;">
                                            <i class="fas fa-inbox" style="font-size: 2rem; margin-bottom: 1rem; display: block;"></i>
                                            No hay registros de visitas aún
                                        </td>
                                    </tr>
                                <?php else: ?>
                                    <?php $rank = 1; foreach (array_slice($stats['paginas_populares'], 0, 5, true) as $pagina => $cantidad): ?>
                                        <tr>
                                            <td>
                                                <?php if ($rank <= 3): ?>
                                                    <span class="badge-rank"><?php echo $rank; ?></span>
                                                <?php else: ?>
                                                    <span class="badge bg-secondary"><?php echo $rank; ?></span>
                                                <?php endif; ?>
                                            </td>
                                            <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;">
                                                <i class="fas fa-file-alt" style="color: #3498db; margin-right: 0.5rem;"></i>
                                                <?php echo htmlspecialchars(substr($pagina, 0, 25)) . (strlen($pagina) > 25 ? '...' : ''); ?>
                                            </td>
                                            <td>
                                                <span class="badge bg-primary"><?php echo number_format($cantidad); ?></span>
                                            </td>
                                        </tr>
                                        <?php $rank++; ?>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function toggleSidebar() {
            const sidebar = document.querySelector('.sidebar');
            sidebar.classList.toggle('show');
        }
        
        // Auto-hide sidebar on mobile when clicking outside
        document.addEventListener('click', function(e) {
            const sidebar = document.querySelector('.sidebar');
            const hamburger = document.querySelector('.hamburger-menu');
            
            if (window.innerWidth <= 768) {
                if (!sidebar.contains(e.target) && !hamburger.contains(e.target)) {
                    sidebar.classList.remove('show');
                }
            }
        });
        
        // Close sidebar when window is resized to desktop
        window.addEventListener('resize', function() {
            const sidebar = document.querySelector('.sidebar');
            if (window.innerWidth > 768) {
                sidebar.classList.remove('show');
            }
        });

        // Subida rápida
        const quickForm = document.getElementById('quickUploadForm');
        const quMsg = document.getElementById('quMsg');
        const btnLimpiar = document.getElementById('btnLimpiarUpload');

        if (quickForm) {
            quickForm.addEventListener('submit', async function(e){
                e.preventDefault();
                quMsg.style.color = '#6c757d';
                quMsg.textContent = 'Subiendo...';
                const formData = new FormData(quickForm);
                try {
                    const res = await fetch('upload_ajax.php', { method: 'POST', body: formData });
                    const data = await res.json();
                    if (data.success) {
                        quMsg.style.color = '#27ae60';
                        quMsg.textContent = 'Archivo subido correctamente';
                        quickForm.reset();
                    } else {
                        quMsg.style.color = '#e74c3c';
                        quMsg.textContent = data.message || 'Error al subir archivo';
                    }
                } catch (err) {
                    quMsg.style.color = '#e74c3c';
                    quMsg.textContent = 'Error de conexión';
                }
            });
        }

        if (btnLimpiar) {
            btnLimpiar.addEventListener('click', function(){
                quickForm.reset();
                quMsg.textContent = '';
            });
        }
    </script>
</body>
</html>