/*Rede Neural construida a partir da biblioteca FANN. Essa rede
resolve o problema de identificação de tráfego anômalo na rede.
Primeiro vou testar se a rede funciona e identifica o trafego 
anômalo, pra depois eu modularizar e fazer ela pegar dados em
tempo real. A criação desta rede teve com base uns arquivos de 
exemplos da fann(xor_sample.cpp) por facilitar a sua compreensão milho
autor:Victor Grudtner Boell
Substituir a biblioteca fann_cpp.h*/

#include "floatfann.h"
#include "fann_cpp.h"

#include <iostream>
#include <iomanip>
#include <ios>

/*Taxa de aprendizagem: 0.01
Supervisionado
Backpropagation
8 em cada interna
Função de ativação sigmoidal
treinamento por lote
*/

/*função responsável por criar e fazer funcionar a RNA. Como
ainda está em "treinamento" não preciso me preocupar tanto
em criar ela bem robusta. hehe XGH (:*/
void redeFANN(){
	
	/*depois vou fazer com que esses parâmetros sejam passados
	dinamicamente pelo usuário*/
	const float taxa_aprendizagem = 0.01f;
	const unsigned int numero_camadas = 4;
	const float momentum = 0.9f;
	const unsigned int numero_epocas = 2000;
	const unsigned int neuron_entradas = 56;
    	const unsigned int neuron_escondida = 8;
	const unsigned int neuron_saidas = 1;
    	/*não me pergunte o porque disso, ainda não sei. rsrsrsrs*/
    	const float taxa_erro_desejado = 0.01f;
    	const unsigned int interacoes_entre_logs = 1; /* :p */

    /*criando a rede neural*/
    FANN::neural_net rede;
    /*create_standard cria uma backpropagation toda interconectada. Nessa 
    arquitetura temos uma rede de 4 camadas: 55 entradas, duas internas com 8
    cada e uma saída.*/
    rede.create_standard(numero_camadas, neuron_entradas, neuron_escondida, neuron_escondida, neuron_saidas); 

    /*definindo taxa de aprendizagem*/
    rede.set_learning_rate(taxa_aprendizagem);

    /*definindo as funções de ativação das camadas*/
    rede.set_activation_function_hidden(FANN::SIGMOID);
    rede.set_activation_function_output(FANN::SIGMOID);

    /*setando o algoritmo de treinamento da rede*/
    rede.set_training_algorithm(FANN::TRAIN_BATCH);

    /*setando o momentummmmmmm*/
    rede.set_learning_momentum(momentum);

    /*strutura que vai receber os dados de treinamento*/
    FANN::training_data dados;

    /*lendo os dados de um arquivo e verificando se tudo
    ocorreu bem. preciso melhorar as mensagens de erro. rsrsrsr*/
    try{
    	/*lendo tudo corretamente, vai funfar*/
    	if(dados.read_train_from_file("fann_file.data")){
    		
    		rede.init_weights(dados);
    		/*iniciando o treinamento*/
    		rede.train_on_data(dados, numero_epocas, interacoes_entre_logs, taxa_erro_desejado);

    	}
    }catch(...){
    	std::cerr << "Erro: falha numero 2" << std::endl;
    }
}


/*função principal para testes*/
int main(int argc, char** argv){

	/*simpels controle de erros*/
	try{
		/*uma pequena sincronização de entrada e saida 
		dos buffers. Verificar depois se há algum ganho
		de desempenho uo apenas faz funcionar as coisas*/
		std::ios::sync_with_stdio(true);
		redeFANN();
	}catch(...){
		std::cerr << "Erro: falha numero 1" << std::endl;
	}

	return 0;
}
