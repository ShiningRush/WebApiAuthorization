package com.yiban.coreservice.client;

public class Main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		System.out.println("It is owned Yiban.CoreService.");
		CredentialManager.Init(
				"your appId", 
				"your secret", 
				"192.168.27.32", 
				"53001",
				30);
		
		try {
			System.out.println(CredentialManager.getInstance().getAccessToken());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
