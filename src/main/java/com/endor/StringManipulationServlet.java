package com.endor;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;

/**
 * Servlet that exercises vulnerable Apache Commons Lang 2.6 code
 * This version has CVE-2014-2882 and other vulnerabilities
 */
@WebServlet(name = "StringManipulationServlet", urlPatterns = "/StringManipulationServlet")
public class StringManipulationServlet extends HttpServlet {
    
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        
        HtmlUtil.printHtmlHeader(response);
        HtmlUtil.startBody(response);
        HtmlUtil.printMenu(response);
        HtmlUtil.printCurrentTitle("String Manipulation (Vulnerable)", response);
        
        // Form for user input
        String form = "<form method=\"GET\" action=\"StringManipulationServlet\">" +
                "Input string: <input type=\"text\" name=\"input\" id=\"input\" value=\"\"><br><br>" +
                "Operation: <select name=\"operation\" id=\"operation\">" +
                "<option value=\"escape\">Escape HTML</option>" +
                "<option value=\"escapeSql\">Escape SQL</option>" +
                "<option value=\"escapeJavaScript\">Escape JavaScript</option>" +
                "<option value=\"reverse\">Reverse</option>" +
                "<option value=\"abbreviate\">Abbreviate</option>" +
                "</select><br><br>" +
                "<input type=\"submit\" value=\"Process\">" +
                "</form><br><br>";
        out.println(form);
        
        String input = request.getParameter("input");
        String operation = request.getParameter("operation");
        
        if (input != null && !input.isEmpty()) {
            out.println("<h3>Result:</h3>");
            out.println("<p><strong>Input:</strong> " + input + "</p>");
            out.println("<p><strong>Operation:</strong> " + (operation != null ? operation : "none") + "</p>");
            
            try {
                String result = processString(input, operation);
                out.println("<p><strong>Output:</strong> " + result + "</p>");
                
                // Also demonstrate other vulnerable StringUtils methods
                out.println("<h3>Additional StringUtils Operations:</h3>");
                out.println("<p>Is empty: " + StringUtils.isEmpty(input) + "</p>");
                out.println("<p>Is blank: " + StringUtils.isBlank(input) + "</p>");
                out.println("<p>Reversed: " + StringUtils.reverse(input) + "</p>");
                out.println("<p>Abbreviated (10 chars): " + StringUtils.abbreviate(input, 10) + "</p>");
                out.println("<p>Capitalized: " + StringUtils.capitalise(input) + "</p>");
                
            } catch (Exception e) {
                out.println("<p style=\"color:red;\">Error: " + e.getMessage() + "</p>");
                e.printStackTrace();
            }
        }
        
        out.println("</body>");
        out.println("</html>");
    }
    
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        doGet(request, response);
    }
    
    private String processString(String input, String operation) {
        if (operation == null) {
            return input;
        }
        
        switch (operation) {
            case "escape":
                // Using vulnerable StringEscapeUtils.escapeHtml() from Commons Lang 2.6
                return StringEscapeUtils.escapeHtml(input);
                
            case "escapeSql":
                // Using vulnerable StringEscapeUtils.escapeSql() from Commons Lang 2.6
                return StringEscapeUtils.escapeSql(input);
                
            case "escapeJavaScript":
                // Using vulnerable StringEscapeUtils.escapeJavaScript() from Commons Lang 2.6
                return StringEscapeUtils.escapeJavaScript(input);
                
            case "reverse":
                return StringUtils.reverse(input);
                
            case "abbreviate":
                return StringUtils.abbreviate(input, 20);
                
            default:
                return input;
        }
    }
}

