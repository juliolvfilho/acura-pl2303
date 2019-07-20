### Funções C# para comunicação com leitor de cartões mifare 1k/4k da marca Acura&copy;
Testada com o modelo Acura AM-310 mas deve funcionar com qualquer marca que utilize o chip PL2303 da GIGA-TMS que é detectado como "Prolific Technology".

Essas funções foram criadas tão somente para a gravação e leitura de um código de matrícula no cartão mifare.

Referência: http://www.gigatms.com.tw/products-detail1.asp?pid=81

##### Considerações Gerais
1. Adicione as dlls GNetPlus e MifareReader em seu projeto.
2. Copie a classe Acura para o seu projeto da forma que melhor funcionar para você.
3. Defina suas chaves de leitura e escrita na classe antes de usar.

##### Funções disponíveis

| Nome | Descrição |
| - | - |
| `Conectar` | Realiza conexão com o leitor de cartões. |
| `Conectada` | Verifica se o leitor de cartões está conectado e se comunicando corretamente. |
| `Desconectar` | Desconecta do leitor de cartões liberando a porta. |
| `ID` | Realiza a leitura do ID do cartão. |
| `CartaoPosicionado` | Informa se existe um cartão mifare posicionado ao alcance do leitor. |
| `Ler` | Realiza a leitura do número de matrícula armazenado no cartão. |
| `Gravar` | Grava um número de matrícula no cartão. |
| `AdicionarEvento` | Registra um callback para quando o leitor de cartões disparar um evento. |
| `RemoverEventos` | Remove todos os eventos registrados anteriormente pela função acima. |
| `PrepararCartaoVirgem` | Prepara um cartão mifare em branco (de fábrica) para ser utilizado pelo sistema com as chaves definidas. |
