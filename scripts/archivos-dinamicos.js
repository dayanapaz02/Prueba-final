/**
 * Script para cargar y mostrar archivos dinámicamente desde el CSV
 */

class ArchivosDinamicos {
    constructor(containerId, categoria) {
        this.container = document.getElementById(containerId);
        this.categoria = categoria;
        this.archivos = [];
        
        if (this.container) {
            this.init();
        }
    }
    
    init() {
        this.cargarArchivos();
        this.setupEventListeners();
    }
    
    async cargarArchivos() {
        try {
            const response = await fetch(`leer_archivos_public.php?categoria=${this.categoria}&formato=html`);
            const html = await response.text();
            
            if (this.container) {
                this.container.innerHTML = html;
            }
        } catch (error) {
            console.error('Error al cargar archivos:', error);
            this.mostrarError();
        }
    }
    
    mostrarError() {
        if (this.container) {
            this.container.innerHTML = `
                <div class="error-message">
                    <i class="fas fa-exclamation-triangle"></i>
                    <p>Error al cargar los archivos. Por favor, inténtelo de nuevo.</p>
                </div>
            `;
        }
    }
    
    setupEventListeners() {
        // Recargar archivos cada 30 segundos
        setInterval(() => {
            this.cargarArchivos();
        }, 30000);
    }
    
    // Método estático para recargar archivos en una categoría específica
    static recargarCategoria(categoria) {
        const containers = document.querySelectorAll(`[data-categoria="${categoria}"]`);
        containers.forEach(container => {
            const loader = new ArchivosDinamicos(container.id, categoria);
        });
    }
}

// Funciones globales para descargar y ver archivos
function descargarArchivo(nombreArchivo) {
    // Usar el sistema de descarga existente
    const url = `descargar.php?file=${encodeURIComponent(nombreArchivo)}`;
    
    // Crear enlace temporal para descarga
    const link = document.createElement('a');
    link.href = url;
    link.download = nombreArchivo;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    // Registrar evento de descarga
    registrarEventoDescarga(nombreArchivo);
}

function verArchivo(nombreArchivo) {
    // Abrir archivo en nueva ventana
    const url = `descargar.php?file=${encodeURIComponent(nombreArchivo)}&view=1`;
    window.open(url, '_blank');
    
    // Registrar evento de visualización
    registrarEventoVisualizacion(nombreArchivo);
}

function registrarEventoDescarga(nombreArchivo) {
    // Usar el sistema de tracking existente
    fetch(`scripts/registrar_evento.php?archivo=${encodeURIComponent(nombreArchivo)}&accion=descarga`)
        .catch(error => console.error('Error al registrar descarga:', error));
}

function registrarEventoVisualizacion(nombreArchivo) {
    // Usar el sistema de tracking existente
    fetch(`scripts/registrar_evento.php?archivo=${encodeURIComponent(nombreArchivo)}&accion=apertura`)
        .catch(error => console.error('Error al registrar visualización:', error));
}

// Inicializar cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', function() {
    // Auto-detectar contenedores de archivos
    const containers = document.querySelectorAll('[data-archivos-categoria]');
    containers.forEach(container => {
        const categoria = container.getAttribute('data-archivos-categoria');
        const id = container.id || `archivos-${categoria}-${Math.random().toString(36).substr(2, 9)}`;
        container.id = id;
        
        new ArchivosDinamicos(id, categoria);
    });
});

// CSS para los archivos dinámicos
const archivosCSS = `
<style>
.archivos-container {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 0; /* sin espacios entre tarjetas */
    margin: 0; /* sin margen extra en la sección */
    padding: 0; /* sin padding lateral */
    align-items: stretch;
}

/* Normalizar tamaño de tarjetas para que todas se vean iguales */
.archivos-container .seminario-card {
    height: 360px; /* alto uniforme */
    display: flex;
    flex-direction: column;
    width: 100%;
    margin: 0; /* sin espacio alrededor de cada tarjeta */
}

.archivos-container .seminario-image {
    height: 180px; /* altura fija de imagen */
}

.archivos-container .seminario-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
}

.archivo-item {
    background: white;
    border-radius: 12px;
    padding: 0;
    box-shadow: 0 4px 20px rgba(0,0,0,0.1);
    transition: all 0.3s ease;
    border: 1px solid #e9ecef;
    overflow: hidden;
    position: relative;
}

.archivo-item:hover {
    transform: translateY(-8px);
    box-shadow: 0 12px 40px rgba(0,0,0,0.15);
}

.archivo-header {
    background: linear-gradient(135deg, #2E7D32, #388E3C);
    color: white;
    padding: 1.5rem;
    position: relative;
}

.archivo-header::after {
    content: '';
    position: absolute;
    bottom: -10px;
    left: 50%;
    transform: translateX(-50%);
    width: 0;
    height: 0;
    border-left: 10px solid transparent;
    border-right: 10px solid transparent;
    border-top: 10px solid #388E3C;
}

.archivo-icon {
    display: flex;
    align-items: center;
    gap: 0.8rem;
    margin-bottom: 0.5rem;
}

.archivo-icon i {
    font-size: 2rem;
    opacity: 0.9;
}

.archivo-icon h3 {
    margin: 0;
    font-size: 1.2rem;
    font-weight: 700;
    line-height: 1.3;
    word-wrap: break-word;
}

.archivo-meta {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    margin: 0;
    font-size: 0.9rem;
    opacity: 0.95;
}

.archivo-meta span {
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.archivo-meta i {
    font-size: 0.9rem;
    width: 16px;
}

.archivo-body {
    padding: 1.5rem;
}

.archivo-details {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-bottom: 1.5rem;
}

.detail-item {
    text-align: center;
    padding: 0.8rem;
    background: #f8f9fa;
    border-radius: 8px;
    border-left: 3px solid #2E7D32;
}

.detail-label {
    font-size: 0.8rem;
    color: #6c757d;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 0.3rem;
}

.detail-value {
    font-size: 1rem;
    color: #2E7D32;
    font-weight: 700;
}

.archivo-actions {
    display: flex;
    gap: 0.8rem;
    justify-content: center;
}

.btn-download, .btn-view {
    background: linear-gradient(135deg, #2E7D32, #388E3C);
    color: white;
    border: none;
    padding: 0.8rem 1.5rem;
    border-radius: 8px;
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex: 1;
    justify-content: center;
}

.btn-download:hover, .btn-view:hover {
    background: linear-gradient(135deg, #388E3C, #2E7D32);
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(46,125,50,0.4);
}

.btn-view {
    background: linear-gradient(135deg, #8B4513, #A0522D);
}

.btn-view:hover {
    background: linear-gradient(135deg, #A0522D, #8B4513);
    box-shadow: 0 6px 20px rgba(139,69,19,0.4);
}

.no-files-message {
    text-align: center;
    padding: 4rem 2rem;
    color: #6c757d;
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.1);
}

.no-files-message i {
    font-size: 4rem;
    margin-bottom: 1.5rem;
    color: #dee2e6;
}

.no-files-message h4 {
    font-size: 1.5rem;
    margin-bottom: 0.8rem;
    color: #495057;
}

.no-files-message p {
    font-size: 1.1rem;
    margin: 0;
    color: #6c757d;
}

.error-message {
    text-align: center;
    padding: 2rem;
    color: #dc3545;
    background: #f8d7da;
    border-radius: 12px;
    border: 1px solid #f5c6cb;
}

.error-message i {
    font-size: 2.5rem;
    margin-bottom: 1rem;
}

.loading-message {
    text-align: center;
    padding: 3rem 2rem;
    color: #6c757d;
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.1);
}

.loading-message i {
    font-size: 3rem;
    margin-bottom: 1rem;
    color: #2E7D32;
}

.loading-message p {
    font-size: 1.2rem;
    margin: 0;
    font-weight: 600;
}

@media (max-width: 768px) {
    .archivos-container {
        grid-template-columns: 1fr;
        gap: 1.5rem;
        padding: 0 0.5rem;
    }
    
    .archivo-details {
        grid-template-columns: 1fr;
        gap: 0.8rem;
    }
    
    .archivo-actions {
        flex-direction: column;
        gap: 0.6rem;
    }
    
    .btn-download, .btn-view {
        padding: 1rem 1.5rem;
        font-size: 1rem;
    }
}
</style>
`;

// Insertar CSS en el head
document.head.insertAdjacentHTML('beforeend', archivosCSS);