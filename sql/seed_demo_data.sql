USE [prueba_auditoria]
GO

SET NOCOUNT ON
GO

-- Usuarios base
IF NOT EXISTS (SELECT 1 FROM dbo.Usuarios WHERE Usuario = 'admin')
BEGIN
    INSERT INTO dbo.Usuarios (Usuario, Password, Nombre, Email, DNI, Tarjeta_Credito, Salario, Rol, FechaCreacion, Activo)
    VALUES
        ('admin', 'admin123', 'Administrador Demo', 'admin@demo.local', '12345678', '4111111111111111', 8000.00, 'ADMIN', GETDATE(), 1),
        ('jlopez', 'clave123', 'Juan Lopez', 'juan.lopez@demo.local', '87654321', '4012888888881881', 2500.00, 'VENTAS', GETDATE(), 1),
        ('mgarcia', 'pass2024', 'Maria Garcia', 'maria.garcia@demo.local', '11223344', '5555555555554444', 3200.00, 'RRHH', GETDATE(), 1);
END
GO

-- Trabajadores (sensibles)
IF NOT EXISTS (SELECT 1 FROM dbo.Trabajadores WHERE DNI = '87654321')
BEGIN
    INSERT INTO dbo.Trabajadores
        (DNI, Nombre, Apellidos, FechaNacimiento, Direccion, Telefono, Email, NumeroTarjeta, CVV, SueldoMensual,
         HistorialMedico, Antecedentes, FechaContratacion, Activo)
    VALUES
        ('87654321', 'Juan', 'Lopez Perez', '1990-05-20', 'Av. Siempre Viva 123', '999888777', 'juan.lopez@demo.local',
         '4012888888881881', '123', 2500.00, 'Alergia a penicilina', 'Ninguno', GETDATE(), 1),
        ('11223344', 'Maria', 'Garcia Rojas', '1988-11-02', 'Jr. Las Flores 456', '988777666', 'maria.garcia@demo.local',
         '5555555555554444', '456', 3200.00, 'Asma leve', 'Ninguno', GETDATE(), 1);
END
GO

-- Pedidos vinculados a usuarios
IF NOT EXISTS (SELECT 1 FROM dbo.Pedidos)
BEGIN
    INSERT INTO dbo.Pedidos (UsuarioID, FechaPedido, Total, Estado)
    SELECT u.UsuarioID, GETDATE(), 150.00, 'Pendiente'
    FROM dbo.Usuarios u
    WHERE u.Usuario IN ('admin', 'jlopez', 'mgarcia');
END
GO

-- Cuentas para pruebas de transferencias
IF NOT EXISTS (SELECT 1 FROM dbo.Cuentas)
BEGIN
    INSERT INTO dbo.Cuentas (NumeroCuenta, Saldo, UsuarioID, TipoCuenta, FechaApertura)
    SELECT '0001-0000001', 5000.00, u.UsuarioID, 'Ahorros', GETDATE()
    FROM dbo.Usuarios u WHERE u.Usuario = 'jlopez'
    UNION ALL
    SELECT '0001-0000002', 3000.00, u.UsuarioID, 'Ahorros', GETDATE()
    FROM dbo.Usuarios u WHERE u.Usuario = 'mgarcia';
END
GO

-- Ventas_Old para el log de error del SP (si aplica)
IF NOT EXISTS (SELECT 1 FROM dbo.Ventas_Old)
BEGIN
    INSERT INTO dbo.Ventas_Old (Fecha, Total, Procesado)
    VALUES (GETDATE(), 0.00, 0);
END
GO

-- Ejemplos de llamada al SP vulnerable
-- EXEC dbo.MAESTRO_importarUsuario_demo_inseguro @json = N'[{"usuario":"jlopez","clave":"clave123","aplicacion":"VENTAS"}]'
-- EXEC dbo.MAESTRO_importarUsuario_demo_inseguro @json = N'[{"usuario":"87654321","clave":"cualquiera","aplicacion":"RRHH"}]'
