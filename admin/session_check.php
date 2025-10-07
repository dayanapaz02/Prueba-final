<?php
/**
 * Verificación de sesión para el panel de administración
 * Incluir este archivo en cualquier página que requiera autenticación
 */

session_start();

// Verificar si está logueado
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    // Guardar la URL actual para redirigir después del login
    $_SESSION['redirect_after_login'] = $_SERVER['REQUEST_URI'];
    
    // Redirigir al login
    header('Location: login.php');
    exit();
}

// Verificar que el archivo de usuarios existe
$usuarios_file = '../data/usuarios.csv';
if (!file_exists($usuarios_file)) {
    session_destroy();
    header('Location: login.php?error=system_error');
    exit();
}
?>
