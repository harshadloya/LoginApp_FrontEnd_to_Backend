package edu.assignment;

import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Random;
import java.util.regex.Pattern;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

public class LoginPage {
	
	private static final Random RANDOM = new SecureRandom();
    private static final String SALT_ALPHABETS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final int ITERATIONS = 10000;
    private static final int KEY_LENGTH = 256;
    private JFrame frame;
    private JLabel lbl;
    
	public static void main(String[] args) 
	{
		LoginPage lp = new LoginPage();
		lp.baseUI();
		lp.initializeUI();
	}
	
	public void baseUI()
	{
		frame = new JFrame("Login Page");
		frame.setBounds(500, 250, 400, 400);
		
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		frame.setVisible(true);
	}
	
	public void initializeUI()
	{
		frame.getContentPane().removeAll();
		
		JPanel panel = new JPanel();
		panel.setLayout(null);		
		
		JLabel usernameLbl = new JLabel();
		usernameLbl.setText("Username: ");
		usernameLbl.setBounds(50, 100, 100, 30);
		usernameLbl.setFont(new Font(usernameLbl.getFont().getFontName(), Font.PLAIN, usernameLbl.getFont().getSize() + 4));
		
		
		JTextField usernameFld = new JTextField();
		usernameFld.setBounds(165, 103, 150, 30);
		usernameFld.setFont(new Font(usernameFld.getFont().getFontName(), Font.PLAIN, usernameFld.getFont().getSize() + 4));
		
		JLabel passwordLbl = new JLabel();
		passwordLbl.setText("Password: ");
		passwordLbl.setBounds(50, 150, 100, 30);
		passwordLbl.setFont(new Font(passwordLbl.getFont().getFontName(), Font.PLAIN, passwordLbl.getFont().getSize() + 4));
		
		
		JPasswordField passwordFld = new JPasswordField();
		passwordFld.setBounds(165, 153, 150, 30);
		passwordFld.setFont(new Font(passwordFld.getFont().getFontName(), Font.PLAIN, passwordFld.getFont().getSize() + 4));
		
		
		JButton submit = new JButton("Submit");
		submit.setBounds(110, 210, 100, 30);
		submit.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent arg0) 
			{
				validate(usernameFld.getText(), passwordFld.getText());
			}
		});
		
		lbl = new JLabel();
		lbl.setBounds(135, submit.getY() + 45, 200, 25);
		lbl.setFont(new Font(lbl.getFont().getFontName(), Font.PLAIN, lbl.getFont().getSize() + 4));
		lbl.setVisible(false);
		
		panel.add(usernameLbl);
		panel.add(usernameFld);
		panel.add(passwordLbl);
		panel.add(passwordFld);
		panel.add(submit);
		panel.add(lbl);
		
		frame.add(panel);
		frame.revalidate();
		frame.repaint();
	}
	
	public void validate(String username, String password)
	{
		boolean user = validateUsername(username);
		boolean pass = false;
		
		if(user)
		{
			pass = validatePassword(password);
			if(pass)
			{
				//check in db only if all validations pass
				checkDB(username, password);
			}
			else
			{
				updateUI("old", username, "pass");
			}
		}
		else
			updateUI("old", username, "user");
	}
	
	public boolean validateUsername(String username)
	{
		String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";
		Pattern pat = Pattern.compile(emailRegex);
		 
		if(!pat.matcher(username).matches())
			return false;
		return true;
	}
	
	public boolean validatePassword(String password)
	{
		if(password.length() < 5 || password.length() > 9)
		{
			return false;
		}
		else if(!password.substring(0,1).matches("[A-Z]"))
		{
			//updateUI("old", username, "pass");
			return false;
		}
		else if(!password.substring(password.length()-1, password.length()).matches("\\$|#|!") )
		{
			//updateUI("old", username, "pass");
			return false;
		}
		else if(!password.matches("(.*[a-z].*)") && !password.matches("(.+[0-9].+)"))
		{
			//updateUI("old", username, "pass");
			return false;
		}
		return true;
	}
	
	//If user available in DB, log him in else create user and log him in
	public void checkDB(String username, String password)
	{
		Connection conn = null;
		PreparedStatement preStmt = null;
		String query = null;
		
		try
		{
			Class.forName("oracle.jdbc.driver.OracleDriver");
			conn = DriverManager.getConnection("jdbc:oracle:thin:@localhost:1521:xe","harshad","harshad");
			
			query = "select salt, password from users where username = '" + username + "'";
			preStmt = conn.prepareStatement(query);
			
			ResultSet rs = preStmt.executeQuery();
			
			if(rs.next())
			{
				String hashedPassword = generateHash(password, rs.getString(1));
				if(hashedPassword.equals(rs.getString(2)))
					updateUI("old", username, "success");
				else
					updateUI("old", username, "failed");
			}
			else
			{
				String salt = getSalt(30);
				String hashedPassword = generateHash(password, salt);
				//String hashedSalt = generateHash(salt, "");
				
				query = "insert into users (username, salt, password) values ('"+username+"', '"+salt+"', '"+hashedPassword+"')";
				preStmt = conn.prepareStatement(query);
				preStmt.executeQuery();
				conn.commit();
				
				updateUI("new", username, "success");
			}
		} 
		catch (ClassNotFoundException e) 
		{
			System.err.println("JDBC Driver not found");
			e.printStackTrace();
		}
		catch (SQLException e) 
		{
			e.printStackTrace();		
		} 
		
		
		finally 
		{
			try 
			{
				conn.close();
			} catch (SQLException e) 
			{
				System.err.println("Cannot close connection to db");
				e.printStackTrace();
				System.exit(1);
			}
		}
	}
	
	
	public static String getSalt(int length) 
	{
		int randLen = SALT_ALPHABETS.length();
		
		StringBuilder retVal = new StringBuilder(length);
        for (int i = 0; i < length; i++) 
        {
            retVal.append(SALT_ALPHABETS.charAt(RANDOM.nextInt(randLen)));
        }
        return retVal.toString();
    }
	
	public String generateHash(String password, String salt)
	{
		String encryptionString = "";
		if(!salt.equals(""))
		{
			encryptionString = salt + password;
		}
		else
		{
			encryptionString = password;
		}
		try 
		{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(encryptionString.getBytes());
			return Base64.getEncoder().encodeToString(md.digest());
		} 
		catch (NoSuchAlgorithmException e) 
		{
			e.printStackTrace();
		}
		return "";
	}
	
	public void updateUI(String type, String username, String status)
	{
		if(status.equals("failed"))
		{
			lbl.setText("Login Failed");
			lbl.setVisible(true);
		}
		else if(status.equals("pass"))
		{
			lbl.setText("Password Invalid");
			lbl.setVisible(true);
		}
		else if(status.equals("user"))
		{
			lbl.setText("Username Invalid");
			lbl.setVisible(true);
		}
		else
		{
			
			frame.getContentPane().removeAll();
			
			lbl.setText("Login Successful");
			lbl.setVisible(true);
			
			JPanel panel = new JPanel();
			panel.setLayout(null);
			
			
			JLabel lbl2 = new JLabel();
			lbl2.setBounds(frame.getWidth() - 290, 15, 200, 25);
			
			JButton btn = new JButton("Logout");
			btn.setBounds(lbl2.getWidth()+75, lbl2.getY()+35, 75, 25);
			btn.addActionListener(logoutAction);
			
			if(type.equals("new"))
				lbl2.setText("Welcome " + username);
			
			panel.add(lbl);
			panel.add(lbl2);
			panel.add(btn);
			frame.add(panel);
		}
		
		
		frame.revalidate();
		frame.repaint();
	}
	
	private ActionListener logoutAction = new ActionListener() 
	{
		
		@Override
		public void actionPerformed(ActionEvent arg0) 
		{
			frame.getContentPane().removeAll();
			initializeUI();
		}
	};

}
