package com.example;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.BufferedReader;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONObject;
import org.json.JSONArray;
import java.util.Map;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

@WebServlet({"/formtoken", "/validate", "/ipn"})
public class McwServlet extends HttpServlet {
    
    // Componentes principales para la plantilla, las propiedades y el controlador
    private McwProperties properties;
    private McwController mcwController;

    @Override
    public void init() throws ServletException {
	// Iniciando las propiedades y el controlador
	properties = new McwProperties();
	mcwController = new McwController();
    }
    
    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        response.addHeader("Access-Control-Allow-Origin", "http://localhost:5173");
        response.addHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE");
        response.addHeader("Access-Control-Allow-Headers", "Content-Type");
        response.addHeader("Access-Control-Allow-Credentials", "true");
        response.setStatus(HttpServletResponse.SC_OK);
    }

    /**
     * @@ Manejo de rutas POST @@
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
       	
	response.addHeader("Access-Control-Allow-Origin", "http://localhost:5173");
        response.addHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE");
        response.addHeader("Access-Control-Allow-Headers", "Content-Type");
        response.addHeader("Access-Control-Allow-Credentials", "true");

	// Obtiene la ruta solicitada
        String path = request.getServletPath();
	
	// Definición de las variables a usar
	String krHash;
    	String krAnswer;
	String requestBody;
	JSONObject jsonResponse;	
        	
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

            case "/validate":

		String HMAC_SHA256 = properties.getProperty("HMAC_SHA256");
		
		// Leer el cuerpo de la solicitud
    		StringBuilder jsonBuilderv = new StringBuilder();
    		try (BufferedReader readerv = request.getReader()) {
        		String linev;
        		while ((linev = readerv.readLine()) != null) {
            		jsonBuilderv.append(linev);
        		}
    		} catch (IOException e) {
        		response.setContentType("application/json");
        		response.getWriter().write("false");
       	 		break;
    		}

		String jsonString = jsonBuilderv.toString();
    		JsonObject jsonObject;
    		try {
        		JsonParser parser = new JsonParser(); // Si usas Gson
        		jsonObject = parser.parse(jsonString).getAsJsonObject();
    		} catch (JsonSyntaxException e) {
        		response.setContentType("application/json");
        		response.getWriter().write("false");
        		break;
    		}

		// Asignando los valores de la respuesta en las variables
    		krHash = jsonObject.get("kr-hash").getAsString();
    		krAnswer = jsonObject.get("kr-answer").getAsString();

		// Válida que la respuesta sea íntegra comprando el hash recibido en el 'kr-hash' con el generado con el 'kr-answer'
		if (!mcwController.checkHash(krHash, HMAC_SHA256, krAnswer)){
			response.setContentType("application/json");
        		response.getWriter().write("false");
			break;
		}

		response.setContentType("application/json");
    		response.getWriter().write("true");

		break;

	   
	   case "/ipn":

		requestBody = mcwController.readJsonBody(request);
            	ObjectMapper mapper = new ObjectMapper();
            	Map<String, String> jsonMap = mapper.readValue(requestBody, new TypeReference<Map<String, String>>() {});

		// Asignando los valores de la respuesta IPN en las variables
		krHash = jsonMap.get("kr-hash");
            	krAnswer = jsonMap.get("kr-answer");
		
		String PASSWORD = properties.getProperty("PASSWORD");


		// Válida que la respuesta sea íntegra comprando el hash recibido en el 'kr-hash' con el generado con el 'kr-answer'
		if (!mcwController.checkHash(krHash, PASSWORD, krAnswer)){
			System.out.println("Notification Error");
			break;
		}

		// Procesa la respuesta del pago
		jsonResponse = new JSONObject(krAnswer);
		JSONArray transactionsArray = jsonResponse.getJSONArray("transactions");
		JSONObject transactions = transactionsArray.getJSONObject(0);
		
		// Verifica el orderStatus PAID
		String orderStatus = jsonResponse.getString("orderStatus");
		String orderId = jsonResponse.getJSONObject("orderDetails").getString("orderId");
		String uuid = transactions.getString("uuid");
		
		// Retornando el OrderStatus
		response.getWriter().write("OK! Order Status is " + orderStatus);

		break;
	   
            default:
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                break;
        }
    }
}

