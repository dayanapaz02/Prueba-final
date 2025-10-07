<?php
session_start();

// Verificar si está logueado
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: login.php');
    exit();
}

// Archivos CSV
$archivos_csv = '../data/archivos_registro.csv';
$data_dir = '../data/';

// Crear directorio si no existe
if (!is_dir($data_dir)) {
    mkdir($data_dir, 0755, true);
}

// Crear CSV si no existe
if (!file_exists($archivos_csv)) {
    $handle = fopen($archivos_csv, 'w');
    fputcsv($handle, ['id', 'nombre_archivo', 'archivo_original', 'autor', 'año', 'destino', 'fecha_subida', 'tamaño']);
    fclose($handle);
}

// Procesar acciones
$mensaje = '';
$tipo_mensaje = '';

if ($_POST) {
    $accion = $_POST['accion'] ?? '';
    
    if ($accion === 'subir') {
        $autor = trim($_POST['autor'] ?? '');
        $año = trim($_POST['año'] ?? '');
        $destino = $_POST['destino'] ?? '';
        
        if (isset($_FILES['archivo']) && $_FILES['archivo']['error'] === UPLOAD_ERR_OK) {
            if (!empty($autor) && !empty($año) && !empty($destino)) {
                $archivo_info = $_FILES['archivo'];
                $nombre_original = $archivo_info['name'];
                $nombre_archivo = uniqid() . '_' . preg_replace('/[^a-zA-Z0-9._-]/', '', $nombre_original);
                $ruta_destino = '../uploads/' . $destino . '/';
                
                // Crear directorio de destino si no existe
                if (!is_dir($ruta_destino)) {
                    mkdir($ruta_destino, 0755, true);
                }
                
                $ruta_completa = $ruta_destino . $nombre_archivo;
                
                if (move_uploaded_file($archivo_info['tmp_name'], $ruta_completa)) {
                    // Guardar en CSV
                    $handle = fopen($archivos_csv, 'a');
                    $id = time();
                    $fecha = date('Y-m-d H:i:s');
                    $tamaño = filesize($ruta_completa);
                    
                    fputcsv($handle, [
                        $id,
                        $nombre_archivo,
                        $nombre_original,
                        $autor,
                        $año,
                        $destino,
                        $fecha,
                        $tamaño
                    ]);
                    fclose($handle);
                    
                    $mensaje = "Archivo subido correctamente: " . $nombre_original;
                    $tipo_mensaje = 'success';
                } else {
                    $mensaje = "Error al subir el archivo";
                    $tipo_mensaje = 'error';
                }
            } else {
                $mensaje = "Por favor, complete todos los campos";
                $tipo_mensaje = 'error';
            }
        } else {
            $mensaje = "Error al procesar el archivo";
            $tipo_mensaje = 'error';
        }
    }
    
    if ($accion === 'eliminar') {
        $id = $_POST['id'] ?? '';
        
        if (!empty($id)) {
            // Leer CSV y eliminar archivo
            $archivos = [];
            $handle = fopen($archivos_csv, 'r');
            
            while (($data = fgetcsv($handle)) !== FALSE) {
                if (count($data) >= 8 && $data[0] !== $id) {
                    $archivos[] = $data;
                } else if (count($data) >= 8 && $data[0] === $id) {
                    // Eliminar archivo físico
                    $ruta_archivo = '../uploads/' . $data[5] . '/' . $data[1];
                    if (file_exists($ruta_archivo)) {
                        unlink($ruta_archivo);
                    }
                }
            }
            fclose($handle);
            
            // Reescribir CSV
            $handle = fopen($archivos_csv, 'w');
            fputcsv($handle, ['id', 'nombre_archivo', 'archivo_original', 'autor', 'año', 'destino', 'fecha_subida', 'tamaño']);
            
            foreach ($archivos as $archivo) {
                fputcsv($handle, $archivo);
            }
            fclose($handle);
            
            $mensaje = "Archivo eliminado correctamente";
            $tipo_mensaje = 'success';
        }
    }
}

// Leer archivos registrados
$archivos_registrados = [];
if (file_exists($archivos_csv)) {
    $handle = fopen($archivos_csv, 'r');
    $header = fgetcsv($handle); // Saltar encabezado
    
    while (($data = fgetcsv($handle)) !== FALSE) {
        if (count($data) >= 8) {
            $archivos_registrados[] = [
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
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subir Archivos - Panel Administración IHCAFE</title>
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
        
        /* Cards */
        .card {
            background: white;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            border: none;
            margin-bottom: 2rem;
        }
        
        .card-header {
            background: linear-gradient(135deg, #3498db, #2980b9);
            color: white;
            border-radius: 15px 15px 0 0;
            padding: 1.5rem;
            border: none;
        }
        
        .card-title {
            font-size: 1.3rem;
            font-weight: 600;
            margin: 0;
            display: flex;
            align-items: center;
        }
        
        .card-title i {
            margin-right: 0.8rem;
            font-size: 1.5rem;
        }
        
        .card-body {
            padding: 2rem;
        }
        
        /* Forms */
        .form-group {
            margin-bottom: 1.5rem;
        }
        
        .form-label {
            font-weight: 600;
            color: #2c3e50;
            margin-bottom: 0.5rem;
        }
        
        .form-control {
            border: 2px solid #e9ecef;
            border-radius: 10px;
            padding: 0.8rem 1rem;
            font-size: 1rem;
            transition: all 0.3s ease;
        }
        
        .form-control:focus {
            border-color: #3498db;
            box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
        }
        
        .btn {
            border-radius: 10px;
            padding: 0.8rem 2rem;
            font-weight: 600;
            transition: all 0.3s ease;
            border: none;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #3498db, #2980b9);
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(52, 152, 219, 0.3);
            color: white;
        }
        
        .btn-danger {
            background: linear-gradient(135deg, #e74c3c, #c0392b);
            color: white;
        }
        
        .btn-danger:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(231, 76, 60, 0.3);
            color: white;
        }
        
        .btn-success {
            background: linear-gradient(135deg, #27ae60, #229954);
            color: white;
        }
        
        .btn-success:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(39, 174, 96, 0.3);
            color: white;
        }
        
        /* Tables */
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
        
        .badge {
            padding: 0.4rem 0.8rem;
            border-radius: 15px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        
        .badge.bg-primary {
            background: linear-gradient(135deg, #3498db, #2980b9) !important;
        }
        
        .badge.bg-success {
            background: linear-gradient(135deg, #27ae60, #229954) !important;
        }
        
        .badge.bg-info {
            background: linear-gradient(135deg, #17a2b8, #138496) !important;
        }
        
        /* Alerts */
        .alert {
            border-radius: 10px;
            border: none;
            padding: 1rem 1.5rem;
        }
        
        .alert-success {
            background: linear-gradient(135deg, #d4edda, #c3e6cb);
            color: #155724;
        }
        
        .alert-danger {
            background: linear-gradient(135deg, #f8d7da, #f5c6cb);
            color: #721c24;
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
                <a href="dashboard.php" class="nav-link">
                    <i class="fas fa-home nav-icon"></i>
                    Dashboard
                </a>
            </div>
            <div class="nav-item">
                <a href="#" class="nav-link active">
                    <i class="fas fa-file-alt nav-icon"></i>
                    Subir Archivos
                </a>
            </div>
            <div class="nav-item">
                <a href="../index.html" class="nav-link">
                    <i class="fas fa-globe nav-icon"></i>
                    Sitio Web
                </a>
            </div>
            <div class="nav-item">
                <a href="#" class="nav-link">
                    <i class="fas fa-chart-bar nav-icon"></i>
                    Estadísticas
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
            <h1 class="page-title">Gestión de Archivos</h1>
            <div class="hamburger-menu" onclick="toggleSidebar()">
                <div class="hamburger-line"></div>
                <div class="hamburger-line"></div>
                <div class="hamburger-line"></div>
            </div>
        </div>

        <!-- Content Area -->
        <div class="content-area">
            <!-- Mensajes -->
            <?php if ($mensaje): ?>
                <div class="alert alert-<?php echo $tipo_mensaje === 'success' ? 'success' : 'danger'; ?>" role="alert">
                    <i class="fas fa-<?php echo $tipo_mensaje === 'success' ? 'check-circle' : 'exclamation-triangle'; ?> me-2"></i>
                    <?php echo htmlspecialchars($mensaje); ?>
                </div>
            <?php endif; ?>

            <!-- Card de Subir Archivos -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">
                        <i class="fas fa-cloud-upload-alt"></i>
                        Subir Nuevo Archivo
                    </h2>
                </div>
                <div class="card-body">
                    <form method="POST" enctype="multipart/form-data">
                        <input type="hidden" name="accion" value="subir">
                        
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label for="archivo" class="form-label">
                                        <i class="fas fa-file-pdf me-2"></i>Seleccionar Archivo
                                    </label>
                                    <input type="file" class="form-control" id="archivo" name="archivo" 
                                           accept=".pdf,.doc,.docx" required>
                                    <small class="form-text text-muted">Formatos permitidos: PDF, DOC, DOCX</small>
                                </div>
                            </div>
                            
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label for="destino" class="form-label">
                                        <i class="fas fa-folder me-2"></i>Página de Destino
                                    </label>
                                    <select class="form-control" id="destino" name="destino" required>
                                        <option value="">Seleccionar destino...</option>
                                        <option value="simposios">Simposios Latinoamericanos</option>
                                        <option value="seminarios">Seminarios</option>
                                        <option value="cursos">Cursos Regionales</option>
                                        <option value="Otras Investigaciones">Otras investigaciones</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label for="autor" class="form-label">
                                        <i class="fas fa-user me-2"></i>Autor
                                    </label>
                                    <input type="text" class="form-control" id="autor" name="autor" 
                                           placeholder="Nombre del autor" required>
                                </div>
                            </div>
                            
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label for="año" class="form-label">
                                        <i class="fas fa-calendar me-2"></i>Año
                                    </label>
                                    <input type="text" class="form-control" id="año" name="año" 
                                           placeholder="Ej: 2024" required>
                                </div>
                            </div>
                        </div>
                        
                        <div class="text-end">
                            <button type="submit" class="btn btn-success">
                                <i class="fas fa-upload me-2"></i>Subir Archivo
                            </button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Card de Archivos Registrados -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">
                        <i class="fas fa-list-alt"></i>
                        Archivos Registrados (<?php echo count($archivos_registrados); ?>)
                    </h2>
                    <button class="btn btn-primary btn-sm" onclick="generarAutores()">
                        <i class="fas fa-sync-alt me-2"></i>Generar Autores.js
                    </button>
                </div>
                <div class="card-body">
                    <?php if (empty($archivos_registrados)): ?>
                        <div class="text-center py-5">
                            <i class="fas fa-inbox fa-3x text-muted mb-3"></i>
                            <h5 class="text-muted">No hay archivos registrados</h5>
                            <p class="text-muted">Sube tu primer archivo usando el formulario de arriba</p>
                        </div>
                    <?php else: ?>
                        <div class="table-responsive">
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th width="50">#</th>
                                        <th>Archivo</th>
                                        <th>Autor</th>
                                        <th>Año</th>
                                        <th>Destino</th>
                                        <th>Fecha</th>
                                        <th>Tamaño</th>
                                        <th width="100">Acciones</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($archivos_registrados as $index => $archivo): ?>
                                        <tr>
                                            <td>
                                                <span class="badge bg-primary"><?php echo $index + 1; ?></span>
                                            </td>
                                            <td>
                                                <i class="fas fa-file-pdf text-danger me-2"></i>
                                                <strong><?php echo htmlspecialchars($archivo['archivo_original']); ?></strong>
                                            </td>
                                            <td><?php echo htmlspecialchars($archivo['autor']); ?></td>
                                            <td>
                                                <span class="badge bg-info"><?php echo htmlspecialchars($archivo['año']); ?></span>
                                            </td>
                                            <td>
                                                <span class="badge bg-success">
                                                    <?php 
                                                    $destinos = [
                                                        'simposios' => 'Simposios',
                                                        'seminarios' => 'Seminarios',
                                                        'cursos' => 'Cursos',
                                                        'Otras investigaciones' => 'Otras investigaciones'
                                                    ];
                                                    echo $destinos[$archivo['destino']] ?? $archivo['destino'];
                                                    ?>
                                                </span>
                                            </td>
                                            <td><?php echo date('d/m/Y', strtotime($archivo['fecha_subida'])); ?></td>
                                            <?php $tamanoBytes = isset($archivo['tamaño']) && is_numeric($archivo['tamaño']) ? (float)$archivo['tamaño'] : 0; ?>
                                            <td><?php echo number_format($tamanoBytes / 1024, 1); ?> KB</td>
                                            <td>
                                                <button class="btn btn-danger btn-sm" 
                                                        onclick="confirmarEliminar('<?php echo $archivo['id']; ?>', '<?php echo htmlspecialchars($archivo['archivo_original']); ?>')">
                                                    <i class="fas fa-trash"></i>
                                                </button>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal de Confirmación -->
    <div class="modal fade" id="confirmModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-exclamation-triangle text-warning me-2"></i>
                        Confirmar Eliminación
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <p>¿Estás seguro de que deseas eliminar el archivo:</p>
                    <p><strong id="nombreArchivo"></strong></p>
                    <p class="text-danger"><small>Esta acción no se puede deshacer.</small></p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <form method="POST" style="display: inline;">
                        <input type="hidden" name="accion" value="eliminar">
                        <input type="hidden" name="id" id="archivoId">
                        <button type="submit" class="btn btn-danger">
                            <i class="fas fa-trash me-2"></i>Eliminar
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function toggleSidebar() {
            const sidebar = document.querySelector('.sidebar');
            sidebar.classList.toggle('show');
        }
        
        function confirmarEliminar(id, nombre) {
            document.getElementById('archivoId').value = id;
            document.getElementById('nombreArchivo').textContent = nombre;
            new bootstrap.Modal(document.getElementById('confirmModal')).show();
        }
        
        function generarAutores() {
            fetch('generar_autores.php')
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        alert('Archivo autores.js generado correctamente.\nArchivos procesados: ' + data.archivos_procesados);
                    } else {
                        alert('Error: ' + data.message);
                    }
                })
                .catch(error => {
                    alert('Error al generar el archivo de autores');
                    console.error('Error:', error);
                });
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
    </script>
</body>
</html>