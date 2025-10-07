<?php
/**
 * Sistema de Gestión de Usuarios
 * 
 * IMPORTANTE: Este sistema usa archivos CSV para simplicidad de desarrollo.
 * En PRODUCCIÓN se debe usar una base de datos (MySQL, PostgreSQL, etc.)
 * para mayor seguridad y rendimiento.
 */

// Configurar zona horaria
date_default_timezone_set('America/Tegucigalpa');

// Ruta del archivo de usuarios
define('USERS_CSV', __DIR__ . '/../usuarios.csv');

/**
 * Crear archivo de usuarios si no existe
 */
function inicializarArchivoUsuarios() {
    if (!file_exists(USERS_CSV)) {
        $handle = fopen(USERS_CSV, 'w');
        if ($handle) {
            // Escribir encabezados
            fputcsv($handle, ['email', 'password_hash', 'fecha_registro', 'ultimo_login', 'activo']);
            fclose($handle);
            // Establecer permisos seguros
            chmod(USERS_CSV, 0600); // Solo lectura/escritura para el propietario
        }
    }
}

/**
 * Verificar si un email ya está registrado
 * 
 * @param string $email Email a verificar
 * @return bool True si el email existe, false si no
 */
function emailExiste($email) {
    inicializarArchivoUsuarios();
    
    if (!file_exists(USERS_CSV)) {
        return false;
    }
    
    $handle = fopen(USERS_CSV, 'r');
    if ($handle === false) {
        return false;
    }
    
    // Saltar encabezados
    fgetcsv($handle);
    
    while (($data = fgetcsv($handle)) !== false) {
        if (isset($data[0]) && strtolower(trim($data[0])) === strtolower(trim($email))) {
            fclose($handle);
            return true;
        }
    }
    
    fclose($handle);
    return false;
}

/**
 * Registrar un nuevo usuario
 * 
 * @param string $email Email del usuario
 * @param string $password Contraseña en texto plano
 * @return array Resultado de la operación
 */
function registrarUsuario($email, $password) {
    // Validaciones de entrada
    if (empty($email) || empty($password)) {
        return [
            'success' => false,
            'message' => 'Email y contraseña son requeridos'
        ];
    }
    
    // Validar formato de email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return [
            'success' => false,
            'message' => 'Formato de email inválido'
        ];
    }
    
    // Validar longitud de contraseña
    if (strlen($password) < 6) {
        return [
            'success' => false,
            'message' => 'La contraseña debe tener al menos 6 caracteres'
        ];
    }
    
    // Verificar si el email ya existe
    if (emailExiste($email)) {
        return [
            'success' => false,
            'message' => 'Este email ya está registrado'
        ];
    }
    
    // Inicializar archivo si no existe
    inicializarArchivoUsuarios();
    
    // Encriptar contraseña usando password_hash (bcrypt por defecto)
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
    
    // Preparar datos del usuario
    $fechaRegistro = date('Y-m-d H:i:s');
    $usuarioData = [
        strtolower(trim($email)),
        $passwordHash,
        $fechaRegistro,
        '', // ultimo_login (vacío inicialmente)
        '1' // activo (1 = activo, 0 = inactivo)
    ];
    
    // Escribir en el archivo CSV
    $handle = fopen(USERS_CSV, 'a');
    if ($handle === false) {
        return [
            'success' => false,
            'message' => 'Error al crear el archivo de usuarios'
        ];
    }
    
    $resultado = fputcsv($handle, $usuarioData);
    fclose($handle);
    
    if ($resultado === false) {
        return [
            'success' => false,
            'message' => 'Error al registrar el usuario'
        ];
    }
    
    return [
        'success' => true,
        'message' => 'Usuario registrado exitosamente'
    ];
}

/**
 * Autenticar usuario (login)
 * 
 * @param string $email Email del usuario
 * @param string $password Contraseña en texto plano
 * @return array Resultado de la autenticación
 */
function autenticarUsuario($email, $password) {
    // Validaciones de entrada
    if (empty($email) || empty($password)) {
        return [
            'success' => false,
            'message' => 'Email y contraseña son requeridos'
        ];
    }
    
    if (!file_exists(USERS_CSV)) {
        return [
            'success' => false,
            'message' => 'No hay usuarios registrados'
        ];
    }
    
    $handle = fopen(USERS_CSV, 'r');
    if ($handle === false) {
        return [
            'success' => false,
            'message' => 'Error al leer el archivo de usuarios'
        ];
    }
    
    // Saltar encabezados
    fgetcsv($handle);
    
    $usuarioEncontrado = false;
    $datosUsuario = null;
    
    while (($data = fgetcsv($handle)) !== false) {
        if (isset($data[0]) && strtolower(trim($data[0])) === strtolower(trim($email))) {
            $usuarioEncontrado = true;
            $datosUsuario = $data;
            break;
        }
    }
    
    fclose($handle);
    
    if (!$usuarioEncontrado) {
        return [
            'success' => false,
            'message' => 'Usuario no encontrado'
        ];
    }
    
    // Verificar si el usuario está activo
    if (!isset($datosUsuario[4]) || $datosUsuario[4] !== '1') {
        return [
            'success' => false,
            'message' => 'Usuario inactivo'
        ];
    }
    
    // Verificar contraseña usando password_verify
    if (!password_verify($password, $datosUsuario[1])) {
        return [
            'success' => false,
            'message' => 'Contraseña incorrecta'
        ];
    }
    
    // Actualizar último login
    actualizarUltimoLogin($email);
    
    return [
        'success' => true,
        'message' => 'Login exitoso',
        'user_email' => $email
    ];
}

/**
 * Actualizar último login del usuario
 * 
 * @param string $email Email del usuario
 */
function actualizarUltimoLogin($email) {
    if (!file_exists(USERS_CSV)) {
        return;
    }
    
    $usuarios = [];
    $handle = fopen(USERS_CSV, 'r');
    
    if ($handle === false) {
        return;
    }
    
    // Leer encabezados
    $encabezados = fgetcsv($handle);
    
    // Leer todos los usuarios
    while (($data = fgetcsv($handle)) !== false) {
        $usuarios[] = $data;
    }
    fclose($handle);
    
    // Actualizar último login
    $fechaActual = date('Y-m-d H:i:s');
    foreach ($usuarios as &$usuario) {
        if (isset($usuario[0]) && strtolower(trim($usuario[0])) === strtolower(trim($email))) {
            $usuario[3] = $fechaActual; // actualizar ultimo_login
            break;
        }
    }
    
    // Reescribir archivo
    $handle = fopen(USERS_CSV, 'w');
    if ($handle !== false) {
        fputcsv($handle, $encabezados);
        foreach ($usuarios as $usuario) {
            fputcsv($handle, $usuario);
        }
        fclose($handle);
    }
}

/**
 * Verificar si el usuario está autenticado
 * 
 * @return bool True si está autenticado, false si no
 */
function usuarioAutenticado() {
    return isset($_SESSION['usuario_autenticado']) && $_SESSION['usuario_autenticado'] === true;
}

/**
 * Obtener email del usuario autenticado
 * 
 * @return string|null Email del usuario o null si no está autenticado
 */
function obtenerEmailUsuario() {
    if (usuarioAutenticado()) {
        return $_SESSION['user_email'] ?? null;
    }
    return null;
}

/**
 * Cerrar sesión del usuario
 */
function cerrarSesion() {
    // Destruir todas las variables de sesión
    $_SESSION = array();
    
    // Si se desea destruir la sesión completamente, también borrar la cookie de sesión
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    
    // Finalmente, destruir la sesión
    session_destroy();
}

/**
 * Inicializar sesión si no está iniciada
 */
function iniciarSesion() {
    if (session_status() === PHP_SESSION_NONE) {
        // Configuración de seguridad para sesiones
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', isset($_SERVER['HTTPS']));
        ini_set('session.use_strict_mode', 1);
        
        session_start();
    }
}

/**
 * Log de seguridad - registrar intentos de login
 * 
 * @param string $email Email del usuario
 * @param string $resultado Resultado del login (exitoso, fallido, etc.)
 * @param string $ip IP del usuario
 */
function logSeguridad($email, $resultado, $ip = null) {
    if ($ip === null) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'desconocida';
    }
    
    $timestamp = date('Y-m-d H:i:s');
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'desconocido';
    
    $logEntry = "$timestamp - $ip - $email - $resultado - $userAgent\n";
    
    $logFile = __DIR__ . '/../logs/security.log';
    
    // Crear directorio de logs si no existe
    $logDir = dirname($logFile);
    if (!is_dir($logDir)) {
        mkdir($logDir, 0755, true);
    }
    
    // Escribir log
    file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
}

// La función regenerarIdSesion() ya está definida en session_check.php
// No es necesario definirla aquí

// La función establecerSesionUsuario se ha movido a session_check.php
// para evitar redeclaraciones

// Inicializar sistema
inicializarArchivoUsuarios();
?>
