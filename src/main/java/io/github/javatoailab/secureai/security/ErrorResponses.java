package io.github.javatoailab.secureai.security;

import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/** OpenAI-style error bodies, written by hand so filters do not depend on the MVC layer. */
public final class ErrorResponses {

    private ErrorResponses() {
    }

    public static void write(HttpServletResponse response, int status, String type, String message,
                             String requestId) throws IOException {
        write(response, status, type, message, requestId, List.of());
    }

    public static void write(HttpServletResponse response, int status, String type, String message,
                             String requestId, List<String> details) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        if (requestId != null) {
            response.setHeader(InspectedRequest.REQUEST_ID_HEADER, requestId);
        }
        String detailJson = details.stream().map(d -> "\"" + escape(d) + "\"").collect(Collectors.joining(","));
        response.getWriter().write("{\"error\":{\"type\":\"" + escape(type) + "\",\"message\":\"" + escape(message)
                + "\",\"details\":[" + detailJson + "]"
                + (requestId == null ? "" : ",\"request_id\":\"" + escape(requestId) + "\"") + "}}");
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
