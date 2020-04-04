package com.formacionbdi.springboot.app.oauth.clients;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

import com.formacionbdi.springboot.app.usuarios.commons.models.entity.Usuario;

//indicar el nombre del microservicio con el quien nos queremos comunicar
@FeignClient(name="servicio-usuarios")
public interface UsuarioFeignClient {

	/*@RequestParam porque username es un parametro del request*/
	@GetMapping("/usuarios/search/buscar-username")
	public Usuario findByUsername(@RequestParam String username);
	
	@PutMapping("/usuarios/{id}")
	public Usuario update(@RequestBody Usuario usuario, @PathVariable Long id);
	
	
}
