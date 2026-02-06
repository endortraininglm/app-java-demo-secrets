package com.endor;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.text.StringSubstitutor;

/**
 * Servlet that exercises vulnerable Apache Commons Text 1.9 code
 * This version has CVE-2022-42889 (Text4Shell) - Critical vulnerability
 * Allows arbitrary code execution through string interpolation
 */
@WebServlet(name = "TextSubstitutionServlet", urlPatterns = "/TextSubstitutionServlet")
public class TextSubstitutionServlet extends HttpServlet {
    
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        
        HtmlUtil.printHtmlHeader(response);
        HtmlUtil.startBody(response);
        HtmlUtil.printMenu(response);
        HtmlUtil.printCurrentTitle("Text Substitution (Vulnerable - CVE-2022-42889)", response);
        
        // Warning about the vulnerability
        out.println("<div style=\"background-color: #ffcccc; padding: 10px; margin: 10px 0; border: 2px solid red;\">");
        out.println("<strong>WARNING:</strong> This servlet uses Apache Commons Text 1.9 which has ");
        out.println("CVE-2022-42889 (Text4Shell) - a critical vulnerability that allows arbitrary code execution.");
        out.println("</div>");
        
        // Form for user input
        String form = "<form method=\"GET\" action=\"TextSubstitutionServlet\">" +
                "Template string: <input type=\"text\" name=\"template\" id=\"template\" " +
                "value=\"${java:version}\" size=\"80\"><br><br>" +
                "<small>Examples: ${java:version}, ${env:USER}, ${script:javascript:java.lang.System.out.println('XSS')}</small><br><br>" +
                "<input type=\"submit\" value=\"Process\">" +
                "</form><br><br>";
        out.println(form);
        
        String template = request.getParameter("template");
        
        if (template != null && !template.isEmpty()) {
            out.println("<h3>Result:</h3>");
            out.println("<p><strong>Template:</strong> " + template + "</p>");
            
            try {
                // Using vulnerable StringSubstitutor.createInterpolator() from Commons Text 1.9
                // This is the vulnerable method that enables CVE-2022-42889
                final StringSubstitutor interpolator = StringSubstitutor.createInterpolator();
                
                // Process the template - this can execute arbitrary code if user input contains
                // script:javascript:, script:groovy:, or other dangerous interpolators
                String result = interpolator.replace(template);
                
                out.println("<p><strong>Interpolated Result:</strong></p>");
                out.println("<pre style=\"background-color: #f0f0f0; padding: 10px; border: 1px solid #ccc;\">");
                out.println(escapeHtml(result));
                out.println("</pre>");
                
                // Also demonstrate other StringSubstitutor methods
                out.println("<h3>Additional Operations:</h3>");
                Map<String, String> valuesMap = new HashMap<String, String>();
                valuesMap.put("name", "User");
                valuesMap.put("age", "25");
                StringSubstitutor simpleSub = new StringSubstitutor(valuesMap);
                String simpleTemplate = "Hello ${name}, you are ${age} years old";
                out.println("<p>Simple substitution: " + simpleSub.replace(simpleTemplate) + "</p>");
                
            } catch (Exception e) {
                out.println("<p style=\"color:red;\">Error: " + escapeHtml(e.getMessage()) + "</p>");
                out.println("<pre style=\"background-color: #ffeeee; padding: 10px;\">");
                e.printStackTrace(new java.io.PrintWriter(out));
                out.println("</pre>");
            }
        }
        
        out.println("</body>");
        out.println("</html>");
    }
    
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        doGet(request, response);
    }
    
    private String escapeHtml(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }
}

