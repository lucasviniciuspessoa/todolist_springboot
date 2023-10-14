package br.com.lucaspessoa.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.lucaspessoa.todolist.user.IUserRespository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRespository userRespository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        var servletPath = request.getServletPath();
        if (servletPath.startsWith("/tasks/")) {
            // pegar auth. (user e senha)
            var authorization = request.getHeader("Authorization");
            // System.out.println("Authorization");
            // System.out.println(authorization);

            var authEncoded = authorization.substring("Basic".length()).trim();
            System.out.println(authEncoded);
            // encode / decode
            byte[] authDecode = Base64.getDecoder().decode(authEncoded);

            System.out.println(authDecode);

            var authString = new String(authDecode);

            System.out.println(authString);
            String[] credentials = authString.split(":");
            String username = credentials[0];
            String password = credentials[1];

            System.out.println(username);
            System.out.println(password);

            // validar user

            var user = this.userRespository.findByUsername(username);
            if (user == null) {
                response.sendError(401, "Usuário sem autorização.");
            } else {
                // validar senha
                var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                if (passwordVerify.verified) {
                    request.setAttribute("idUser", user.getId());
                    filterChain.doFilter(request, response);

                } else {
                    response.sendError(401);
                }
                // segue viagem

            }

        } else {
            filterChain.doFilter(request, response);
        }

    }
}
