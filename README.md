# gerar_monitor
Script Bash Linux que gera um /monitor eu seu servidor VPS Rocky Linux para a Stack: Kpatch + SELinux + Logrotate + Nginx + ModSecurity + Certbot + PM2 + N8N

Este cript deve ser salvo em um diretório onde somente o root tenha acesso , e executado a cada 15 minutos via crontab.

O script é feito 100% em bash, e gera 03 páginas .HTML a cada execução. O diretório onde as páginas devem ser criadas/salvas precisa ser em usuário onde o Nginx/Apache consiga ter acesso. E lembre de proteger esse diretório com autenticação.

Edite o script para configurar as variáveis para o seu ambiente, e sempre adote os Path completos para cada binário executável. 