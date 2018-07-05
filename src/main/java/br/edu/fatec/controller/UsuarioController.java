package br.edu.fatec.controller;

import java.net.URI;
import java.security.Principal;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import br.edu.fatec.exception.AppException;
import br.edu.fatec.model.Usuario;
import br.edu.fatec.repository.AuthorityRepository;
import br.edu.fatec.repository.UsuarioRepository;
import br.edu.fatec.request.ApiResponse;
import br.edu.fatec.security.Authority;
import br.edu.fatec.security.AuthorityName;
import br.edu.fatec.service.UsuarioService;

@RestController
@RequestMapping("/usuario")
public class UsuarioController {

	@Autowired
	private UsuarioService usuarioService;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private AuthorityRepository authorityRepository;

	@Autowired
	private UsuarioRepository usuarioRepository;

	/* Adicionaer novo usuario */
	@CrossOrigin
	@RequestMapping(value = "/save", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE, headers = "Accept=application/json")
	@ResponseStatus(HttpStatus.CREATED)
	public void salvar(@RequestBody Usuario usuario, HttpServletRequest request, HttpServletResponse response)
			throws Exception {
		usuarioService.salvarUsuario(usuario);
		response.addHeader("Location", request.getServerName() + ":" + request.getServerPort()
				+ request.getServletPath() + "/usuario/getById?id=" + usuario.getId());
	}

	/* Busca um usuario */
	@RequestMapping(value = "/getByNome/{nome}", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<Collection<Usuario>> pesquisarUsuarios(@PathVariable("nome") String nome) {
		return new ResponseEntity<Collection<Usuario>>(usuarioService.buscar(nome), HttpStatus.OK);
	}

	/* Busca usuarios pelo nome e sobrenome */
	@RequestMapping(value = "/get/{nome}/{sobrenome}")
	public ResponseEntity<Collection<Usuario>> usuarioByNomeAndSobrenome(@PathVariable("nome") String nome,
			@PathVariable("sobrenome") String sobrenome) {
		return new ResponseEntity<Collection<Usuario>>(usuarioService.buscaNomeSobrenome(nome, sobrenome),
				HttpStatus.OK);
	}

	/* Busca os usuarios de um determinado evento */
	@RequestMapping(value = "/getByEvento/{nomeEvento}")
	public ResponseEntity<Collection<Usuario>> pesquisarUsuariosEvento(@PathVariable("nomeEvento") String nomeEvento) {
		return new ResponseEntity<Collection<Usuario>>(usuarioService.buscarUsuarioEvento(nomeEvento), HttpStatus.OK);
	}

	/* Pegar usuario pelo id */
	@RequestMapping(value = "/getById")
	public ResponseEntity<Usuario> getUsuario(@RequestParam(value = "id", defaultValue = "1") Long id) {
		Optional<Usuario> usuario = usuarioService.buscar(id);
		if (usuario == null) {
			return new ResponseEntity<Usuario>(HttpStatus.NOT_FOUND);
		}
		return new ResponseEntity<Usuario>(HttpStatus.OK);
	}

	@RequestMapping(value = "/getAll", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<Collection<Usuario>> getAll() {
		return new ResponseEntity<Collection<Usuario>>(usuarioService.todos(), HttpStatus.OK);
	}

	@RequestMapping(value = "/currentUser", produces = MediaType.APPLICATION_JSON_VALUE)
	@CrossOrigin
	// @PreAuthorize("hasHole('ROLE_USER')")
	public Map<String, Object> home(Principal principal) {
		Map<String, Object> model = new HashMap<String, Object>();
//		model.put("id", UUID.randomUUID().toString());
		model.put("content", "Hello " + principal.getName());
		return model;
	}

	@PreAuthorize("permitAll()")
	@SuppressWarnings("unchecked")
	@PostMapping("/signup")
	@CrossOrigin
	public ResponseEntity<?> registerUser(@RequestBody Usuario request) {
		if (usuarioRepository.existsByNome(request.getNome())) {
			return new ResponseEntity(new ApiResponse(false, "Username jah existe!"), HttpStatus.BAD_REQUEST);
		}

		if (usuarioRepository.existsByEmail(request.getEmail())) {
			return new ResponseEntity(new ApiResponse(false, "Email ja esta em uso!"), HttpStatus.BAD_REQUEST);
		}

		Usuario usuario = new Usuario();
		usuario.setId(request.getId());
		usuario.setNome(request.getNome());
		usuario.setSobrenome(request.getSobrenome());
		usuario.setEmail(request.getEmail());
		usuario.setSenha(request.getSenha());
		usuario.setEnabled(request.getEnabled());
		usuario.setLastPasswordResetDate(request.getLastPasswordResetDate());
		usuario.setSenha(passwordEncoder.encode(usuario.getSenha()));

		Authority userAuthority = authorityRepository.findByName(AuthorityName.ROLE_ADMIN)
				.orElseThrow(() -> new AppException("Authority nao gravado!"));

		Usuario user = usuarioRepository.save(usuario);

		URI location = ServletUriComponentsBuilder.fromCurrentContextPath().path("/signup")
				.buildAndExpand(user.getNome()).toUri();

		return ResponseEntity.created(location).body(new ApiResponse(true, "User registered successfully"));

	}

}
