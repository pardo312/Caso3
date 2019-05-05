package TestGenerator;



import java.io.BufferedWriter;
import java.io.PrintStream;

import cliente.Cliente;
import uniandes.gload.core.Task;

public class ClienteServerTask
  extends Task
{
  private static int id = 0;
 Cliente client;
  int tasks;
  static int contFail = 0;
  int gbt;
  int puerto;
  String linea;
  BufferedWriter writer;
  
  public void fail()
  {
	  contFail++;
    System.out.println("FAIL_TEST");
  }
  
  public void success()
  {
	  
    System.out.println("OK_TEST" + id);
  }
  
  public void getReady(BufferedWriter writer, int tasks, int gbt, int puerto, String linea)
  {
    this.tasks = tasks;
    this.gbt = gbt;
    this.puerto = puerto;
    this.linea = linea;
    this.writer = writer;
  }
  
  public void execute()
  {
    try
    {
      this.client = new Cliente("localhost", this.puerto,this.id);
      
      this.client.getReady(this.linea, this.writer);
      this.client.executeProtocol();
    }
    catch (Exception e)
    {
      e.printStackTrace();
      fail();
    }
  }
}
