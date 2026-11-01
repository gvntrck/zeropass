=== ZeroPass Login ===
Contributors: gvntrck
Tags: login, passwordless, authentication, security
Requires at least: 5.0
Tested up to: 6.4
Requires PHP: 7.4
Stable tag: 4.5.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Login sem complicações. Seus usuários acessam sua plataforma com links seguros enviados por e-mail.

== Description ==

Com o ZeroPass Login, seus usuários acessam sua plataforma com links seguros enviados por e-mail. Sem senhas, sem estresse – apenas segurança e simplicidade.
Ideal para quem deseja melhorar a experiência do usuário e aumentar a segurança, eliminando as senhas tradicionais.

== Installation ==

1. Faça o upload dos arquivos do plugin para a pasta `/wp-content/plugins/zeropass-login` no seu servidor, ou instale diretamente pelo painel do WordPress.
2. Ative o plugin através do menu 'Plugins' no WordPress.
3. Configure os remetentes e opções de e-mail nas configurações do plugin.

== Changelog ==

= 4.5.0 =
* Adiciona inglês aos textos padrão do front-end e dos e-mails quando o idioma do site é inglês, preservando textos personalizados e o painel em português.

= 4.4.1 =
* Reescreve as descrições da aba Shortcodes explicando o que cada um faz e o que é enviado por email.

= 4.4.0 =
* Adiciona o shortcode `[passwordless_reset_link]` para redefinição de senha via link enviado por email, sem exibir a senha em texto puro.
* Adiciona a aba "Reset por Link" no painel para configurar o email, a validade do link e o redirecionamento após a redefinição.

= 4.3.0 =
* Adiciona o shortcode `[passwordless_change_password]` para o usuário logado alterar a senha via AJAX, mantendo a sessão ativa.
* Adiciona a aba "Alterar Senha" no painel para configurar os requisitos de força da senha.

= 4.2.5 =
* Isola o POST de confirmação do login em uma rota específica para permitir uma exceção no antispam do WP Cerber.

= 4.1.18 =
* Adiciona paginação e botão de atualização assíncrona na aba de logs do painel.

= 4.1.17 =
* Corrige o fuso horário dos logs para exibição em `America/Sao_Paulo`.

= 4.1.16 =
* Corrige o reenvio do formulário de link mágico no `F5` usando redirecionamento após o `POST`.

= 4.1.15 =
* Adiciona a aba administrativa "Link de login" com listagem centralizada dos links diretos gerados para usuários.
