package TestGenerator;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Security;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;


public class Generator {

	private LoadGenerator generator;
	private ClienteServerTask work;
	
	
	//TODO CAMBIO DE CODIGO ---
	private BufferedWriter writer;
	
	public Generator( String tasks, String gbt, String nThreads) throws Exception{
		
		getReady(nThreads,Integer.parseInt(tasks), Integer.parseInt(gbt));
		work = createTask();
		String linea = nThreads + ";" + tasks + ";" + gbt + ";";
		work.getReady(writer,Integer.parseInt(tasks), Integer.parseInt(gbt), 8083, linea );
		generator = new LoadGenerator("Client - Server Load Test", Integer.parseInt(tasks), work, Integer.parseInt(gbt));
		generator.generate();
		System.out.println("-----------------------------------");
		 System.out.println("Fallos Ocurridos" + work.contFail);
	}
	
	private ClienteServerTask createTask(){
		System.out.println("Nueva tarea");
		return new ClienteServerTask();
	}
	
	//TODO CAMBIO DE CODIGO ---
	@SuppressWarnings("unused")
	void getReady(String nThreads, int tasks, int gbt){
		try {
			String tasksS = String.valueOf(tasks);
			String gbtS = String.valueOf(gbt);
			File testFile = new File("./data/test_nTh-"+ nThreads +"_T-" + tasks +"_GBT-" + gbt+ "_SS.csv");
			writer = new BufferedWriter(new FileWriter(testFile));
			writer.write("Num;Threads;Carga;GBT;TiempoVer;CPU;TiempoResp;" + "\n");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		@SuppressWarnings("unused")
		Generator gen = null;
		String tasks = "", gbt = "", nthreads = "";
		int time = 0;
		BufferedReader consoleIn = new BufferedReader(new InputStreamReader(System.in));
		System.out.println("---- TEST DE CARGA ----");
		try{
			System.out.println("Ingrese la cantidad de threads del servidor:");
			nthreads = consoleIn.readLine();
			System.out.println("Ingrese el numero de tareas que desea ejecutar:");
			tasks = consoleIn.readLine();
			System.out.println("Ingrese el tiempo en ms que desea poner entre cada tarea:");
			gbt = consoleIn.readLine();
			gen = new Generator(tasks, gbt, nthreads);
		}
		catch(Exception e){
			e.printStackTrace();
		}
		
		double in = System.currentTimeMillis(); double end = 0;
		
		if(tasks.equals(80)){
			time = 80;
		}
		else if(tasks.equals("200")){
			time = 115;
		}
		else if(tasks.equals("400")){
			time = 260;
		}
		System.out.println("el writer se cerrara en " + time +" segundos");//TODO se cambia dependiendo del test

		
		while((end/1000) < time){
			end = System.currentTimeMillis() - in;
		}
		
		try {
			System.out.println("El writer se ha cerrado");
			gen.writer.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
