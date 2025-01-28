<p align="center">
  <img src="https://github.com/izipay-pe/Imagenes/blob/main/logos_izipay/logo-izipay-banner-1140x100.png?raw=true" alt="Formulario" width=100%/>
</p>

# Server-PaymentForm-Servlet-Java

## Índice

➡️ [1. Introducción](#-1-introducci%C3%B3n)  
🔑 [2. Requisitos previos](#-2-requisitos-previos)  
🚀 [3. Ejecutar ejemplo](#-3-ejecutar-ejemplo)  
🔗 [4. APIs](#4-APIs)  
💻 [4.1. FormToken](#41-formtoken)  
💳 [4.2. Validación de firma](#42-validaci%C3%B3n-de-firma)  
📡 [4.3. IPN](#43-ipn)  
📮 [5. Probar desde POSTMAN](#-5-probar-desde-postman)  
📚 [6. Consideraciones](#-6-consideraciones)

## ➡️ 1. Introducción

En este manual podrás encontrar una guía paso a paso para configurar un servidor API REST (Backend) en **[Servlet]** para la pasarela de pagos de IZIPAY. **El actual proyecto no incluye una interfaz de usuario (Frontend)** y debe integrarse con un proyecto de Front. Te proporcionaremos instrucciones detalladas y credenciales de prueba para la instalación y configuración del proyecto, permitiéndote trabajar y experimentar de manera segura en tu propio entorno local.
Este manual está diseñado para ayudarte a comprender el flujo de la integración de la pasarela para ayudarte a aprovechar al máximo tu proyecto y facilitar tu experiencia de desarrollo.

<p align="center">
  <img src="https://i.postimg.cc/KYpyqYPn/imagen-2025-01-28-082121144.png" alt="Formulario"/>
</p>

## 🔑 2. Requisitos Previos

- Comprender el flujo de comunicación de la pasarela. [Información Aquí](https://secure.micuentaweb.pe/doc/es-PE/rest/V4.0/javascript/guide/start.html)
- Extraer credenciales del Back Office Vendedor. [Guía Aquí](https://github.com/izipay-pe/obtener-credenciales-de-conexion)
- Para este proyecto utilizamos Apache Tomcat 9.
- Apache Maven 3.9.9
- Java 17 o superior
  
> [!NOTE]
> Tener en cuenta que, para que el desarrollo de tu proyecto, eres libre de emplear tus herramientas preferidas.

## 🚀 3. Ejecutar ejemplo

### Instalar Apache Tomcat 9

Apache Tomcat es una implementación libre y de código abierto de las tecnologías Jakarta Servlet, Jakarta Expression Language y WebSocket.

1. Dirigirse a la página web de [Apache Tomcat](https://tomcat.apache.org/download-90.cgi).
2. Descargarlo e instalarlo.
3. Inicia los servicios de Apache Tomcart.

### Clonar el proyecto
```sh
git clone https://github.com/izipay-pe/Server-PaymentForm-Servlet-Java.git
``` 

### Datos de conexión 

Reemplace **[CHANGE_ME]** con sus credenciales de `API REST` extraídas desde el Back Office Vendedor, revisar [Requisitos previos](#-2-requisitos-previos).

- Editar el archivo `src/main/resources/config.properties` en la ruta raiz del proyecto:
```java
# Archivo para la configuración de las crendeciales de comercio
#
# Identificador de la tienda
USERNAME=CHANGE_ME_USER_ID

# Clave de Test o Producción
PASSWORD=CHANGE_ME_PASSWORD

# Clave Pública de Test o Producción
PUBLIC_KEY=CHANGE_ME_PUBLIC_KEY

# Clave HMAC-SHA-256 de Test o Producción
HMAC_SHA256=CHANGE_ME_HMAC_SHA_256
```

### Ejecutar proyecto

### Ejecutar proyecto

1. Compilar el proyecto usando Maven

```sh
mvn package 
``` 

2.  Mover el archivo `Embedded-PaymentForm-Java.war` creado en la carpeta `/target` a la ruta `/webapps` de Apache Tomcat: `/opt/tomcat/webapps(Linux)` - `C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps(Windows)`

3.  Realizar solicitudes a la ruta : `http://127.0.0.1:8080/Server-PaymentForm-Servlet-Java/`.


## 🔗4. APIs
- 💻 **FormToken:** Generación de formToken y envío de la llave publicKey necesarios para desplegar la pasarela.
- 💳  **Validacion de firma:** Se encarga de verificar la autenticidad de los datos.
- 📩 ️ **IPN:** Comunicación de servidor a servidor. Envío de los datos del pago al servidor.

## 💻4.1. FormToken
Para configurar la pasarela se necesita generar un formtoken. Se realizará una solicitud API REST a la api de creación de pagos:  `https://api.micuentaweb.pe/api-payment/V4/Charge/CreatePayment` con los datos de la compra para generar el formtoken. El servidor devuelve el formToken generado junto a la llave `publicKey` necesaria para desplegar la pasarela

Podrás encontrarlo en el archivo `src/main/java/com/example/McwServlet.java`.

```java
switch (path) {
    case "/formtoken":
		  // Procesando datos POST y almacenándolos en un Map
		  requestBody = mcwController.readJsonBody(request);
      ObjectMapper objectMapper = new ObjectMapper();
      Map<String, String> parameters = objectMapper.readValue(requestBody, 
      new TypeReference<Map<String, String>>() {});

		  //Obtener PublicKey
		  String publicKey = properties.getProperty("PUBLIC_KEY");

		  //Obtenemos el FormToken generado
		  String formToken = mcwController.generateFormToken(parameters);
				
		  // Crear la respuesta
		  jsonResponse = new JSONObject();
      jsonResponse.put("formToken", formToken);
      jsonResponse.put("publicKey", publicKey);        
      response.setContentType("application/json");
      response.setCharacterEncoding("UTF-8");
        
      // Retornar el formToken y el publicKey
      response.getWriter().write(jsonResponse.toString());
      break;
```
Podrás acceder a esta API a través:
```bash
http://127.0.0.1:8080/Server-PaymentForm-Servlet-Java/formToken
```
ℹ️ Para más información: [Formtoken](https://secure.micuentaweb.pe/doc/es-PE/rest/V4.0/javascript/guide/embedded/formToken.html)

## 💳4.2. Validación de firma
Se configura la función `checkHash` que realizará la validación de los datos recibidos por el servidor luego de realizar el pago mediante el parámetro `kr-answer` utilizando una clave de encriptación definida en `key`. Podrás encontrarlo en el archivo `src/main/java/com/example/McwController.java`.

```java
 public boolean checkHash(String krHash, String key, String krAnswer){
	
	String calculatedHash = HmacSha256(krAnswer, key);
	return calculatedHash.equals(krHash);

}
```

Se valida que la firma recibida es correcta. Para la validación de los datos recibidos a través de la pasarela de pagos (front) se utiliza la clave `HMACSHA256`.

```java
    case "/validate":

		String HMAC_SHA256 = properties.getProperty("HMAC_SHA256");
		...
		...
		// Válida que la respuesta sea íntegra comprando el hash recibido en el 'kr-hash' con el generado con el 'kr-answer'
		if (!mcwController.checkHash(krHash, HMAC_SHA256, krAnswer)){
			response.setContentType("application/json");
        		response.getWriter().write("false");
			break;
		}

		response.setContentType("application/json");
    response.getWriter().write("true");

		break;
```

El servidor devuelve un valor `true` verificando si los datos de la transacción coinciden con la firma recibida. Se confirma que los datos son enviados desde el servidor de Izipay.

Podrás acceder a esta API a través:
```bash
http://127.0.0.1:8080/Server-PaymentForm-Servlet-Java/validate
```

ℹ️ Para más información: [Analizar resultado del pago](https://secure.micuentaweb.pe/doc/es-PE/rest/V4.0/kb/payment_done.html)

## 📩4.3. IPN
La IPN es una notificación de servidor a servidor (servidor de Izipay hacia el servidor del comercio) que facilita información en tiempo real y de manera automática cuando se produce un evento, por ejemplo, al registrar una transacción.

Se realiza la verificación de la firma utilizando la función `checkHash`. Para la validación de los datos recibidos a través de la IPN (back) se utiliza la clave `PASSWORD`. Se devuelve al servidor de izipay un mensaje confirmando el estado del pago.

Se recomienda verificar el parámetro `orderStatus` para determinar si su valor es `PAID` o `UNPAID`. De esta manera verificar si el pago se ha realizado con éxito.

Podrás encontrarlo en el archivo `src/main/java/com/example/serverpaymentform/controller/McwSpringboot.java`.

```java
case "/ipn":
    ...
    ...
		String PASSWORD = properties.getProperty("PASSWORD");

		// Válida que la respuesta sea íntegra comprando el hash recibido en el 'kr-hash' con el generado con el 'kr-answer'
		if (!mcwController.checkHash(krHash, PASSWORD, krAnswer)){
			System.out.println("Notification Error");
			break;
		}
    ...
    ...
		// Verifica el orderStatus PAID
		String orderStatus = jsonResponse.getString("orderStatus");
		String orderId = jsonResponse.getJSONObject("orderDetails").getString("orderId");
		String uuid = transactions.getString("uuid");
		
		// Retornando el OrderStatus
		response.getWriter().write("OK! Order Status is " + orderStatus);

		break;
```

Podrás acceder a esta API a través:
```bash
http://127.0.0.1:8080/Server-PaymentForm-Servlet-Java/ipn
```

La ruta o enlace de la IPN debe ir configurada en el Backoffice Vendedor, en `Configuración -> Reglas de notificación -> URL de notificación al final del pago`

<p align="center">
  <img src="https://i.postimg.cc/XNGt9tyt/ipn.png" alt="Formulario" width=80%/>
</p>

ℹ️ Para más información: [Analizar IPN](https://secure.micuentaweb.pe/doc/es-PE/rest/V4.0/api/kb/ipn_usage.html)

## 📡4.3.Pase a producción

Reemplace **[CHANGE_ME]** con sus credenciales de PRODUCCIÓN de `API REST` extraídas desde el Back Office Vendedor, revisar [Requisitos Previos](#-2-requisitos-previos).

- Editar el archivo `src/main/resources/config.properties` en la ruta raiz del proyecto:
```java
# Archivo para la configuración de las crendeciales de comercio
#
# Identificador de la tienda
USERNAME=CHANGE_ME_USER_ID

# Clave de Test o Producción
PASSWORD=CHANGE_ME_PASSWORD

# Clave Pública de Test o Producción
PUBLIC_KEY=CHANGE_ME_PUBLIC_KEY

# Clave HMAC-SHA-256 de Test o Producción
HMAC_SHA256=CHANGE_ME_HMAC_SHA_256
```

## 📮 5. Probar desde POSTMAN
* Puedes probar la generación del formToken desde POSTMAN. Coloca la URL con el metodo POST con la ruta `/formToken`.
  
 ```bash
http://127.0.0.1:8080/Server-PaymentForm-Servlet-Java/formToken
```

* Datos a enviar en formato JSON raw:
 ```node
{
    "amount": 1000,
    "currency": "PEN", //USD
    "orderId": "ORDER12345",
    "email": "cliente@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "phoneNumber": "123456789",
    "identityType": "DNI",
    "identityCode": "ABC123456",
    "address": "Calle principal 123",
    "country": "PE",
    "city": "Lima",
    "state": "Lima",
    "zipCode": "10001"
}
```

## 📚 6. Consideraciones

Para obtener más información, echa un vistazo a:

- [Formulario incrustado: prueba rápida](https://secure.micuentaweb.pe/doc/es-PE/rest/V4.0/javascript/quick_start_js.html)
- [Primeros pasos: pago simple](https://secure.micuentaweb.pe/doc/es-PE/rest/V4.0/javascript/guide/start.html)
- [Servicios web - referencia de la API REST](https://secure.micuentaweb.pe/doc/es-PE/rest/V4.0/api/reference.html)
