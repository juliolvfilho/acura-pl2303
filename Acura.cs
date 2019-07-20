using GIGATMS.NF;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PL2303
{
    /// <summary>
    /// Classe para manipulação da leitora mifare Acura com suporte ao Windows 8 e 7.
    /// <para>Os drivers precisam ser instalados através do Windows Update ou através do site do desenvolvedor (Prolific):</para>
    /// <para>http://www.prolific.com.tw/US/ShowProduct.aspx?p_id=225&amp;pcid=41</para>
    /// </summary>
    public sealed class Acura
    {
        private static MifareReader mf = new MifareReader();

        /// <summary>
        /// Obtém o número da porta COM atualmente usada pela leitora Acura.
        /// </summary>
        public static ushort Porta { get; private set; }

        // defina suas chaves nas variáveis abaixo, essas são as do padrão Henry
        private static string ChaveLeitura = "769973131620h";
        private static string ChaveEscrita = "C728480273A1h";

        public enum TipoEvento
        {
            CartaoPosicionado,
            CartaoRetirado,
            BotaoPressionado,
            Desconhecido
        }

        public delegate void TratadorEvento(TipoEvento tipoEvento);
        private static List<MifareReader.OnReaderEventEventHandler> EventosCadastrados = new List<MifareReader.OnReaderEventEventHandler>();
        private static object bKeyTypeConstant;

        /// <summary>
        /// Realiza conexão com a leitora Acura.
        /// </summary>
        /// <returns>verdadeiro se a conexão foi bem sucedida</returns>
        public static bool Conectar()
        {
            // se já existe uma porta anteriormente definida iremos tentar conectar nela
            if (Acura.Porta > 0)
            {
                if (Acura.Conectar(Acura.Porta)) return true;
            }
            // se a porta não tiver sido definida ainda ou não conseguirmos conectar, vamos procurar
            // a Acura em outras portas
            for (ushort porta = 1; porta <= 30; porta++)
            {
                if (Acura.Conectar(porta))
                {
                    Acura.Porta = porta;
                    return true;
                }
            }

            // Se não conseguiu conectar, retorna
            Acura.Porta = 0;
            return false;
        }

        /// <summary>
        /// Verifica se a Acura está conectada e se comunicando corretamente.
        /// </summary>
        /// <returns>verdadeiro caso esteja devidamente conectada</returns>
        public static bool Conectada()
        {
            // retorna verdadeiro se a porta estiver aberta e se foi possível obter
            // a versão de firmware da acura
            return mf.PortOpen && (mf.GetVersion() != null);
        }

        /// <summary>
        /// Desconecta com a leitora Acura liberando a porta.
        /// </summary>
        /// <returns>verdadeiro em caso de sucesso</returns>
        public static bool Desconectar()
        {
            Acura.Porta = 0;
            Acura.RemoverEventos();
            mf.Reset();
            mf.PortOpen = false;
            return !mf.PortOpen;
        }

        /// <summary>
        /// Informa se existe um cartão mifare posicionado ao alcance da Acura.
        /// </summary>
        /// <returns>verdadeiro caso exista um cartão mifare posicionado</returns>
        public static bool CartaoPosicionado()
        {
            return mf.mfRequest() > 0;
        }

        /// <summary>
        /// Realiza a leitura do conteúdo do cartão.
        /// <para>É necessário antes verificar se o cartão está posicionado</para>
        /// </summary>
        /// <returns>a string contendo a matrícula do cartão ou null em caso de falha</returns>
        public static string Ler()
        {
            // autenticação
            if (Acura.Autenticar())
            {
                // leitura
                byte[] _matricula = new byte[16];
                if (mf.mfRead(1, ref _matricula))
                {
                    // converte bytes para string
                    string matricula = "";
                    foreach (char c in _matricula)
                    {
                        matricula += c;
                    }
                    // reativa o automode pois ele é desabilitado durante a leitura
                    mf.mfAutoMode(true);
                    return matricula;
                }
            }
            mf.mfAutoMode(true);
            return null;
        }

        public static bool Gravar(string matricula, int opcao)
        {
            // suporta no máximo 16 caracteres
            if (matricula.Length <= 16)
            {
                // normaliza a string
                matricula = matricula.PadLeft(16, '0');

                // autenticação
                if (Acura.Autenticar())
                {
                    // converte a matricula string para array de bytes
                    byte[] _matricula = new byte[16];
                    for (int i = 0; i < 16; i++) _matricula[i] = (byte)matricula[i].GetHashCode();

                    // gravação 
                    bool sucesso = false;
                    sucesso = mf.mfWriteEx(0,MifareReader.bKeyTypeConstants.KEY_B,1, _matricula);
                    mf.mfAutoMode(true);
                    return sucesso;

                }
                mf.mfAutoMode(true);
                return false;
            }
            else
            {
                throw new IndexOutOfRangeException("Comprimento máximo da string deve ser 16");
            }
        }

        /// <summary>
        /// Realiza a leitura do ID do cartão.
        /// </summary>
        /// <returns>o número de série do cartão ou null em caso de falha</returns>
        public static string ID()
        {
            string id = null;
            // obtém o ID do cartão
            if (mf.mfAnticollision(ref id))
            {
                // reativa o automode pois ele é desabilitado durante a leitura
                mf.mfAutoMode(true);
                return id;
            }
            else
            {
                // se não conseguiu pode ser porque falta lançar um request para identificar a presença do cartão
                if (Acura.CartaoPosicionado())
                {
                    if (mf.mfAnticollision(ref id))
                    {
                        mf.mfAutoMode(true);
                        return id;
                    }
                }
            }
            mf.mfAutoMode(true);
            return null;
        }

        /// <summary>
        /// Adiciona uma função para ser chamada quando algum evento do tipo <see cref="TipoEvento"/> acorrer
        /// </summary>
        /// <param name="tratador">função a ser chamada</param>
        /// <returns>verdadeiro caso o evento seja adicionado</returns>
        public static bool AdicionarEvento(TratadorEvento tratador)
        {
            if (Acura.Conectada())
            {
                MifareReader.OnReaderEventEventHandler handler = delegate(MifareReader.iReaderEventConstants iReaderEvent)
                {
                    TipoEvento tipo;
                    switch (iReaderEvent)
                    {
                        case MifareReader.iReaderEventConstants.READER_CARD_PRESENT:
                            tipo = TipoEvento.CartaoPosicionado;
                            break;
                        case MifareReader.iReaderEventConstants.READER_CARD_REMOVE:
                            tipo = TipoEvento.CartaoRetirado;
                            break;
                        case MifareReader.iReaderEventConstants.READER_KEY_PRESS:
                            tipo = TipoEvento.BotaoPressionado;
                            break;
                        default:
                            tipo = TipoEvento.Desconhecido;
                            break;
                    }
                    tratador(tipo);
                };
                mf.OnReaderEvent += handler;
                EventosCadastrados.Add(handler);
                return true;
            }
            return false;
        }

        /// <summary>
        /// Remove todos os eventos cadastrados com <see cref="AdicionarEvento"/>
        /// </summary>
        public static void RemoverEventos()
        {
            foreach (MifareReader.OnReaderEventEventHandler evt in EventosCadastrados)
            {
                mf.OnReaderEvent -= evt;
            }
            EventosCadastrados = new List<MifareReader.OnReaderEventEventHandler>();
        }

        /// <summary>
        /// Prepara um cartão mifare em branco (de fábrica) para ser utilizado pelo sistema
        /// </summary>
        /// <returns>verdadeiro em caso de sucesso</returns>
        public static bool PrepararCartaoVirgem()
        {
            if (Acura.Conectada())
            {
                if (Acura.Autenticar_Virgem())
                {
                    bool sucesso = mf.mfAccessCondition(ChaveLeitura, ChaveEscrita, 7, 1, 7, 4); // , 125
                    mf.mfAutoMode(true);
                    return sucesso;
                }
            }
            mf.mfAutoMode(true);
            return false;
        }

        private static bool Conectar(ushort porta)
        {
            // se a Acura já estiver conectada a essa porta, retorna
            if (mf.CommPort == porta && Acura.Conectada())
            {
                return true;
            }
            else
            {
                // por precaução se a porta estiver aberta, fechamos
                Acura.Desconectar();
            }

            // configura a biblioteca para funcionar com a Acura
            mf.Settings = "19200,N,8,1";
            mf.CommPort = (short)porta;
            mf.mfAutoMode(true);

            // tenta a conexão
            mf.PortOpen = true;

            // verifica se conseguiu
            return Acura.Conectada();
        }

        private static bool Autenticar()
        {
            // autentica
            bool autenticado = mf.mfAuthenticate(0, MifareReader.bKeyTypeConstants.KEY_B, ChaveEscrita);
            if (!autenticado)
            {
                // se não autenticou pode ser porque falta lançar um request para identificar a presença do cartão
                if (Acura.CartaoPosicionado())
                {
                    autenticado = mf.mfAuthenticate(0, MifareReader.bKeyTypeConstants.KEY_B, ChaveEscrita);
                }
            }
            return autenticado;
        }

        private static bool Autenticar_Virgem()
        {
            // autentica
            bool autenticado = mf.mfAuthenticate(0, MifareReader.bKeyTypeConstants.KEY_B, "FFFFFFFFFFFF");
            if (!autenticado)
            {
                // se não autenticou pode ser porque falta lançar um request para identificar a presença do cartão
                if (Acura.CartaoPosicionado())
                {
                    autenticado = mf.mfAuthenticate(0, MifareReader.bKeyTypeConstants.KEY_B, "FFFFFFFFFFFF");
                }
            }
            autenticado = true;
            return autenticado;
        }
    }
}
