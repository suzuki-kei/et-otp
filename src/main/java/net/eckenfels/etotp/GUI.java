/*
 * GUI.java - et-otp: GPL Java TOTP soft token by Bernd Eckenfels.
 *
 * Changes:
 * 2016-05-20 Support multiple settings. by suzuki.kei
 * 2016-05-20 Add CLI mode. by suzuki.kei
 * 2016-05-20 Place config file in home directory. by suzuki.kei
 *
 */
package net.eckenfels.etotp;

import java.awt.Color;
import java.awt.Desktop;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.JTextPane;

import net.eckenfels.etotp.Base32.DecodingException;


/**
 * et-OTP GUI main class.
 */
public class GUI implements ActionListener
{
    private static final String VERSION = GUI.class.getPackage().getImplementationVersion();
    private static final String HELPURL = "http://ecki.github.io/et-otp/";
    private static final String PROGNAME = "et-OTP";

    JComboBox<String> settingsNameComboBox;
    JPasswordField passwordField;
    private JTextField textField;
    private JLabel textLabel;
    private JFrame frame;
    private JDialog settingsDialog;
    private JDialog aboutDialog;
    private JTextField settingsName;
    private JTextField settingsCode;
    private JPasswordField settingsPass;
    private static File configFile = new File(System.getProperty("user.home"), ".et-otp.properties");
    private JLabel settingsFileLabel;
    private JLabel statusLabel;
    private boolean logEnabled = true;


    private GUI() { }


    static void buildMainFrame() throws IOException
    {
        GridBagLayout layout = new GridBagLayout();
        GUI gui= new GUI();
        gui.frame = new JFrame(PROGNAME);
        gui.frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        gui.frame.setLayout(layout);

        JMenuBar mb = new JMenuBar();
        JMenu m = new JMenu(PROGNAME); m.setMnemonic(KeyEvent.VK_E);
        JMenuItem mi = new JMenuItem("Settings"); mi.addActionListener(gui);  m.add(mi);
        mi = new JMenuItem("Quit"); mi.addActionListener(gui);  m.add(mi);
        mb.add(m);
        m = new JMenu("Help"); m.setMnemonic(KeyEvent.VK_H);
        mi = new JMenuItem("Manual"); mi.addActionListener(gui);  m.add(mi);
        mi = new JMenuItem("About"); mi.addActionListener(gui);  m.add(mi);
        mb.add(m);
        gui.frame.setJMenuBar(mb);

        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 1;
        c.gridy = 1;
        c.gridheight = 1;
        c.gridwidth = 3;
        c.weighty = 1;
        c.weightx = 1;
        c.insets = new Insets(10, 10, 20, 10);
        c.anchor = GridBagConstraints.NORTH;
        JLabel label = new JLabel(PROGNAME + " Soft Token", JLabel.CENTER);
        label.setFont(new Font("Serif", Font.BOLD, 16));
        gui.frame.add(label, c);

        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 1;
        c.gridy = 2;
        c.gridheight = 1;
        c.gridwidth = 2;
        c.weighty = 0;
        c.weightx = 1;
        c.anchor = GridBagConstraints.CENTER;
        c.insets = new Insets(0,10,5,10);
        label = new JLabel("Setting Name:");
        gui.frame.add(label, c);

        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 1;
        c.gridy = 3;
        c.gridheight = 1;
        c.gridwidth = 2;
        c.weighty = 0;
        c.weightx = 1;
        c.insets = new Insets(0,10,10,10);
        JComboBox<String> settingsNameComboBox = new JComboBox<String>();
        settingsNameComboBox.addActionListener(gui);
        settingsNameComboBox.setFocusable(true);
        gui.frame.add(settingsNameComboBox, c);
        gui.settingsNameComboBox = settingsNameComboBox;

        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 1;
        c.gridy = 4;
        c.gridheight = 1;
        c.gridwidth = 2;
        c.weighty = 0;
        c.weightx = 1;
        c.anchor = GridBagConstraints.CENTER;
        c.insets = new Insets(0,10,5,10);
        label = new JLabel("Unlock Password:");
        gui.frame.add(label, c);

        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 1;
        c.gridy = 5;
        c.gridheight = 1;
        c.gridwidth = 2;
        c.weighty = 0;
        c.weightx = 1;
        c.insets = new Insets(0,10,10,10);
        JPasswordField pwField = new JPasswordField("");
        pwField.addActionListener(gui);
        pwField.setFocusable(true);
        gui.frame.add(pwField, c);
        gui.passwordField = pwField;

        c.fill = GridBagConstraints.BOTH;
        c.gridx = 3;
        c.gridy = 4;
        c.gridheight = 2;
        c.gridwidth = 1;
        c.weighty = 0;
        c.weightx = 0;
        c.ipadx = 0;
        c.insets = new Insets(0,10,10,10);
        c.anchor = GridBagConstraints.CENTER;
        JButton button = new JButton("Calc");
        button.addActionListener(gui);
        gui.frame.add(button, c);

        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 2;
        c.gridy = 6;
        c.gridheight = 1;
        c.gridwidth = 1;
        c.weightx = 1;
        c.weighty = 1;
        c.ipadx = 70;
        c.insets = new Insets(0,10,10,10);
        c.anchor = GridBagConstraints.CENTER;
        JTextField text  = new JTextField("");
        text.setFont(new Font("Dialog", Font.BOLD, 16));
        // text.setFocusable(false);
        text.setEditable(false);
        gui.frame.add(text, c);
        gui.textField = text;

        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 1;
        c.gridy = 6;
        c.gridheight = 1;
        c.gridwidth = 1;
        c.weightx = 2;
        c.weighty = 0;
        c.insets = new Insets(0,20,10,0);
        c.anchor = GridBagConstraints.CENTER;
        label = new JLabel("Your Code:", JLabel.RIGHT);
        gui.frame.add(label, c);

        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 1;
        c.gridy = 7;
        c.gridheight = 1;
        c.gridwidth = 1;
        c.weightx = 2;
        c.weighty = 0;
        c.anchor = GridBagConstraints.SOUTH;
        c.insets = new Insets(0,20,10,0);
        label = new JLabel("Next Code:", JLabel.RIGHT);
        gui.frame.add(label, c);

        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 2;
        c.gridy = 7;
        c.gridheight = 1;
        c.gridwidth = 1;
        c.weightx = 1;
        c.weighty = 0;
        c.anchor = GridBagConstraints.SOUTH;
        c.insets = new Insets(0,10,10,0);
        label = new JLabel("", JLabel.LEFT);
        gui.frame.add(label, c);
        gui.textLabel = label;

        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 1;
        c.gridy = 8;
        c.gridheight = 1;
        c.gridwidth = 3;
        c.weightx = 1;
        c.weighty = 0;
        c.anchor = GridBagConstraints.SOUTH;
        c.insets = new Insets(5,5,5,5);
        label = new JLabel("", JLabel.LEFT);
        gui.frame.add(label, c);
        gui.statusLabel = label;

        gui.frame.addComponentListener(gui.new ShowEvent());

        // now we realize the components
        gui.frame.pack();

        // now we can display it
        gui.frame.setVisible(true);

        gui.reloadSettingsNames();
    }


    @Override
    public void actionPerformed(ActionEvent e)
    {
        log("Event: " + e.getActionCommand() + " " + e.getSource() + " " + e.getID());

        statusLabel.setText(" ");
        statusLabel.setForeground(Color.BLACK);

        if ("Quit".equals(e.getActionCommand()))
        {
            System.exit(0);
        }
        else if ("Manual".equals(e.getActionCommand()))
        {
            try {
                statusLabel.setText("Opening " + HELPURL + " in browser.");
                Desktop.getDesktop().browse(new URI(HELPURL));
            } catch (Exception ignored) { }
        }
        else if ("Save".equals(e.getActionCommand()))
        {
            settingsDialog.setVisible(false);

            String name = settingsName.getText();
            String code = settingsCode.getText();
            char[] pass = settingsPass.getPassword();

            try
            {
                writeSecret(name, code, pass);
                reloadSettingsNames(name);
            }
            catch (Exception ex)
            {
                JOptionPane.showMessageDialog(frame, "Error while writing configuration\n" + ex.getClass().getName() + "\n" + ex.getMessage(), PROGNAME + ": Cannot save configuration", JOptionPane.ERROR_MESSAGE);
            }
/*			catch (DecodingException e2) {
                // TODO Auto-generated catch block
                e2.printStackTrace();
            } catch (IOException e3) {
                // TODO Auto-generated catch block
                e3.printStackTrace();
            } catch (NoSuchAlgorithmException e4) {
                // TODO Auto-generated catch block
                e4.printStackTrace();
            } catch (InvalidKeySpecException e6) {
                // TODO Auto-generated catch block
                e6.printStackTrace();
            } catch (NoSuchPaddingException e7) {
                // TODO Auto-generated catch block
                e7.printStackTrace();
            } catch (InvalidKeyException e8) {
                // TODO Auto-generated catch block
                e8.printStackTrace();
            } catch (IllegalBlockSizeException e9) {
                // TODO Auto-generated catch block
                e9.printStackTrace();
            } catch (BadPaddingException e10) {
                // TODO Auto-generated catch block
                e10.printStackTrace();
            }*/
        }
        else if ("About".equals(e.getActionCommand()))
        {
            if (aboutDialog == null) {
                JDialog d = new JDialog(frame,"About " + PROGNAME, true);
                JTextPane t = new JTextPane();
                t.setContentType("text/html");
                t.setText("<h1>eckes' TOTP Generator (" + PROGNAME + ")</h1><p>This generator can be used to produce a TOTP (RFC 6238) time-based one-time password.</p>" +
                          "<p>This is a so called soft-token, it will be initialized with a specified BASE32 secret. This method is compatible with the 2-step verification methods of Amazon AWS, Dropbox, GitHub, Google, Microsoft and others.</p>" +
                          "<p>This Java Program is from <b>Bernd Eckenfels</b>, it includes some code from the reference implementation if HOTP (RFC 4226) as well as Google's BASE32 implementation from the Google Authenticator project.</p>" +
                          "<p>License: GPLv2.<br/>Version: " + VERSION + "<br/>Homepage: <b>" + HELPURL + "</b></p><p>Config file: <b>" + configFile.getAbsolutePath()+"</b></p>");
                t.validate();
                d.add(t);
                d.setSize(600, 400);
                aboutDialog = d;
            }
            aboutDialog.setVisible(true);
        }
        else if ("Settings".equals(e.getActionCommand()))
        {
            if (settingsDialog == null) {
                JDialog d = new JDialog(frame, PROGNAME + " settings", true);
                buildSettingsDialog(d);
                settingsDialog = d;
            }
            settingsName.setText((String) settingsNameComboBox.getSelectedItem());
            settingsCode.setText("");
            settingsPass.setText("");
            settingsFileLabel.setText("Config File " + (configFile.isFile()?"(exists)":"(missing)"));
            settingsDialog.setVisible(true);
        }
        else if ("Calc".equals(e.getActionCommand()) || (e.getSource() == passwordField))
        {
            try
            {
                char[] pass = passwordField.getPassword();
                String settingsName = (String) settingsNameComboBox.getSelectedItem();

                textField.setText(generateCurrentToken(settingsName, pass));
                textField.requestFocus();
                textField.setCaretPosition(0);
                textField.moveCaretPosition(6);

                textLabel.setText(generateNextToken(settingsName, pass));
                statusLabel.setText("");
            }
            catch (BadPaddingException bp)
            {
                errorText("Bad password.");
            }
            catch (InvalidKeySpecException ik)
            {
                errorText("Password empty or illegal.");
            }
            catch (FileNotFoundException fn)
            {
                errorText("Configuration File not found.");
            }
            catch (IOException io)
            {
                errorText("I/O Error while loading key: " + io.getMessage());
            }
            catch (NoSuchAlgorithmException ns)
            {
                errorText("Crypto Problem: " + ns);
            }
            catch (InvalidKeyException ik)
            {
                errorText("Crypto Key Problem: " + ik);
            }
            catch (Exception ex)
            {
                errorText("Problem: " + ex);
            }
        }
    }

    private String generateCurrentToken(String settingsName, char[] pass)  throws Exception{
        byte[] bytes = readSecret(settingsName, pass);

        long seconds = System.currentTimeMillis() / 1000;
        long t0 = 0l;
        long step = 30l;
        long counter = (seconds - t0) / step;

        return RFC4226.generateOTP(bytes, counter, 6, false, -1);
    }

    private String generateNextToken(String settingsName, char[] pass) throws Exception {
        byte[] bytes = readSecret(settingsName, pass);

        long seconds = System.currentTimeMillis() / 1000;
        long t0 = 0l;
        long step = 30l;
        long counter = (seconds - t0) / step;

        return RFC4226.generateOTP(bytes, counter+1, 6, false, -1);
    }

    private void errorText(String text)
    {
        statusLabel.setForeground(Color.RED);
        statusLabel.setText(text);
    }


    private void writeSecret(String name, String code, char[] pass)
            throws DecodingException, NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, FileNotFoundException, IOException
    {
        if (name == null || name.isEmpty()) {
            throw new RuntimeException("name is required.");
        }
        if (code == null || code.isEmpty()) {
            throw new RuntimeException("code is required.");
        }

        byte[] codeBytes;
        codeBytes = Base32.decode(code);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        rand.nextBytes(salt);
        SecretKey password = f.generateSecret(new PBEKeySpec(pass, salt, 1000, 128));
        // TODO clean pass
        password = new SecretKeySpec(password.getEncoded(), "AES");

        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.ENCRYPT_MODE, password);

        byte[] enc = c.doFinal(codeBytes);

        log("WRITE salt=" + Base32.encode(salt) + " encrypted=" + Base32.encode(enc));

        Properties p = readSettings();
        p.put("key." + name + ".name" , "test");
        p.put("key." + name + ".salt", Base32.encode(salt));
        p.put("key." + name + ".encoded", Base32.encode(enc));
        OutputStream os = new FileOutputStream(configFile);
        p.store(os , PROGNAME + " " + VERSION + " softtokens");
        os.close();
    }

    private void reloadSettingsNames() throws IOException {
        String selectedName = (String) settingsNameComboBox.getSelectedItem();
        reloadSettingsNames(selectedName);
    }

    private void reloadSettingsNames(String selectedName) throws IOException {
        settingsNameComboBox.removeAllItems();
        List<String> settingsNames = readSettingsNames();
        for(String name : settingsNames) {
            settingsNameComboBox.addItem(name);
        }
        if (settingsNames.contains(selectedName)) {
            settingsNameComboBox.setSelectedItem(selectedName);
        }
    }

    private List<String> readSettingsNames() throws IOException {
        Properties properties = readSettings();
        List<String> names = new ArrayList<String>();
        for(Enumeration<Object> enumeration = properties.keys(); enumeration.hasMoreElements();) {
            String key = (String) enumeration.nextElement();
            if (key.matches("key.[^.]+\\.name")) {
                String name = key.split("\\.", 3)[1];
                names.add(name);
            }
        }
        return names;
    }

    private Properties readSettings() throws IOException {
        Properties properties = new Properties();
        if (!configFile.isFile()) {
            return properties;
        }

        InputStream stream = null;
        try {
            stream = new FileInputStream(configFile);
            properties.load(stream);
            return properties;
        } finally {
            if(stream != null) {
                stream.close();
            }
        }
    }

    private byte[] readSecret(String settingsName, char[] pass)
            throws FileNotFoundException, IOException, DecodingException,
            InvalidKeySpecException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException
    {
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        byte[] salt;
        SecretKey password;
        Cipher c;
        byte[] enc;
        Properties p;
        InputStream is = new FileInputStream(configFile);
        p = new Properties();
        p.load(is); is.close();

        salt = Base32.decode((String)p.get("key." + settingsName + ".salt"));
        enc = Base32.decode((String)p.get("key." + settingsName + ".encoded"));

        log("READ salt=" + Base32.encode(salt) + " encrypted=" + Base32.encode(enc));

        password = f.generateSecret(new PBEKeySpec(pass, salt, 1000, 128));
        // TODO: overwrite pass
        password = new SecretKeySpec(password.getEncoded(), "AES");

        log(" password=" + Base32.encode(password.getEncoded()));

        c = Cipher.getInstance("AES");
        c.init(Cipher.DECRYPT_MODE, password);
        byte[] dec = c.doFinal(enc);

        return dec;
    }


    private void buildSettingsDialog(JDialog dia)
    {
        dia.setLayout(new GridBagLayout());
        dia.setSize(640, 300);
        GridBagConstraints c = new GridBagConstraints();

        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 1;
        c.gridy = 1;
        c.weightx = 0;
        c.weighty = 0;
        c.insets = new Insets(10, 10, 10, 10);
        dia.add(new JLabel("Name", JLabel.RIGHT), c);

        c.gridx = 2;
        c.gridy = 1;
        c.weightx = 1;
        c.weighty = 0;
        settingsName = new JTextField();
        dia.add(settingsName, c);

        c.gridx = 1;
        c.gridy = 2;
        c.weightx = 0;
        dia.add(new JLabel("Code (base32):", JLabel.RIGHT), c);

        c.gridx = 2;
        c.gridy = 2;
        c.weightx = 1;
        settingsCode = new JPasswordField();
        dia.add(settingsCode, c);

        c.gridx = 1;
        c.gridy = 3;
        c.weightx = 0;
        dia.add(new JLabel("Password:", JLabel.RIGHT), c);

        c.gridx = 2;
        c.gridy = 3;
        c.weightx = 1;
        settingsPass = new JPasswordField();
        dia.add(settingsPass, c);

        c.gridx = 1;
        c.gridy = 4;
        c.gridwidth = 2;
        c.weightx = 1;
        c.weighty = 1;
        JButton button = new JButton("Save");
        button.addActionListener(this);
        dia.add(button,c);

        String file = configFile.getAbsolutePath();
        c.gridx = 1;
        c.gridy = 5;
        c.weightx = 1;
        c.weighty = 0;
        c.gridwidth = 2;
        c.insets = new Insets(10,10,0,10);
        settingsFileLabel = new JLabel("Config File " + (configFile.isFile()?"(exists)":"(missing)"));
        dia.add(settingsFileLabel, c);

        c.gridx = 1;
        c.gridy = 6;
        c.weightx = 1;
        c.gridwidth = 2;
        c.insets = new Insets(0,10,10,10);
        JLabel label = new JLabel(file);
        dia.add(label, c);
    }

    private void log(String message) {
        if (logEnabled) {
            System.out.println(message);
        }
    }


    /**
     * Main method - does not honor any arguments (yet).
     * @param args ignored
     */
    public static void main(String[] args) throws Exception
    {
        if (args.length > 0) {
            new GUI().runAsCli(args[0]);
        } else {
            buildMainFrame();
        }
    }

    private void runAsCli(String settingsName) throws Exception {
        this.logEnabled = false;
        char[] pass = new char[0];
        String currentToken = generateCurrentToken(settingsName, pass);
        String nextToken = generateNextToken(settingsName, pass);
        System.out.println(String.format("%s (next %s)", currentToken, nextToken));
    }

    class ShowEvent extends ComponentAdapter
    {
        @Override
        public void componentShown(ComponentEvent evt)
        {
            JFrame f = (JFrame)evt.getComponent();
            // we can only request focus when everything is shown
            f.requestFocus();
            f.toFront();
            passwordField.requestFocusInWindow();
        }
    } // end class ShowEvent

} // end class GUI

