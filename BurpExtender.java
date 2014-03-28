//    CSRF Scanner Extension for Burp Suite
//    Copyright (C) 2014  Adrian Hayter
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.

package burp;

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFormattedTextField;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import javax.swing.text.NumberFormatter;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class BurpExtender implements IBurpExtender, IScannerCheck, ITab
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel panel;
    private JScrollPane scroll;
    
    private final Pattern FORM_OPEN_PATTERN = Pattern.compile("<form[^>]*>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL );
    private final Matcher FORM_OPEN_MATCHER = FORM_OPEN_PATTERN.matcher("");
    
    private final Pattern FORM_CLOSE_PATTERN = Pattern.compile("</form[^>]*>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private final Matcher FORM_CLOSE_MATCHER = FORM_CLOSE_PATTERN.matcher("");
    
    private final Color FONT_COLOR = new Color(0xE58925);
    private final BASE64Encoder base64Encoder = new BASE64Encoder();
    private final BASE64Decoder base64Decoder = new BASE64Decoder();
    
    // Issue Types
    private final String NO_TOKEN_IN_REQUEST_PARAMS = "Request vulnerable to Cross-site Request Forgery";
    private final String TOKEN_IN_REQUEST_PARAMS = "Anti-CSRF token detected in request";
    private final String SHORT_TOKEN = "Short Anti-CSRF token value detected";
    private final String NO_TOKEN_IN_RESPONSE_FORM = "Form does not contain an anti-CSRF token";
    private final String TOKEN_IN_RESPONSE_FORM = "Anti-CSRF token detected in form";
    
    // Defaults
    private final String[] DEFAULT_TOKEN_LIST = {"Token", "CSRF", "CSRFtoken", "antiCSRF", "__RequestVerificationToken", "RequestVerificationToken", "antiForgery", "Forgery"};
    private final boolean DEFAULT_CASE_INSENSITIVITY = false;
    private final boolean DEFAULT_MIN_TOKEN = true;
    private final int DEFAULT_MIN_TOKEN_LENGTH = 16;
    private final boolean DEFAULT_NO_TOKEN_REQUESTS = true;
    private final boolean DEFAULT_NO_TOKEN_FORMS = true;
    private final boolean DEFAULT_FOUND_TOKEN_REQUESTS = false;
    private final boolean DEFAULT_FOUND_TOKEN_FORMS = false;
    
    // Settings
    private DefaultListModel<String> tokens;
    private JList tokenList;
    private JCheckBox caseSensitive;
    private JCheckBox tokenLengthCheck;
    private JFormattedTextField tokenLength;
    private int minTokenLength;
    private JCheckBox noTokenRequests;
    private JCheckBox noTokenForms;
    private JCheckBox foundTokenRequests;
    private JCheckBox foundTokenForms;
    
    @Override public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("CSRF Scanner");
        
        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);
        
        // create our UI
        SwingUtilities.invokeLater(new Runnable() 
        {
            @Override
            public void run()
            {
                panel = new JPanel();
                scroll = new JScrollPane(panel, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                scroll.setBorder(BorderFactory.createEmptyBorder());
                
                JLabel title = new JLabel("Cross-site Request Forgery (CSRF) Scanner");
                title.setFont(new Font(title.getFont().getName(), Font.BOLD, 13));
                title.setForeground(FONT_COLOR);
                
                JLabel desc = new JLabel("Configure the list of recognised anti-CSRF tokens and other scanner settings.");
                
                JLabel csrfListLabel = new JLabel("Anti-CSRF Tokens");
                csrfListLabel.setFont(new Font(csrfListLabel.getFont().getName(), Font.PLAIN, 11));
                csrfListLabel.setForeground(FONT_COLOR);
                
                tokens = new DefaultListModel<String>();
                
                tokenList = new JList(tokens);
                JScrollPane scrollPane = new JScrollPane(tokenList);
                scrollPane.setMaximumSize(new Dimension(200, 200));
                scrollPane.setMinimumSize(new Dimension(200, 200));
                
                JButton addToken = new JButton("Add");
                addToken.addActionListener(new ActionListener()
                {
                    @Override public void actionPerformed(ActionEvent e)
                    {
                        String s = (String)JOptionPane.showInputDialog(
                        panel,
                        "Enter an Anti-CSRF Token:",
                        "Add Anti-CSRF Token",
                        JOptionPane.PLAIN_MESSAGE,
                        null,
                        null,
                        "");
                        
                        if (s.trim().length() > 0)
                        {
                            if (!tokens.contains(s))
                            {
                                tokens.addElement(s);
                            }
                        }
                    }
                });
                
                JButton editToken = new JButton("Edit");
                editToken.addActionListener(new ActionListener()
                {
                    @Override public void actionPerformed(ActionEvent e)
                    {
                        int i = tokenList.getSelectedIndex();
                        if (i != -1)
                        {
                            String s = (String)JOptionPane.showInputDialog(
                            panel,
                            "Enter an Anti-CSRF Token:",
                            "Edit Anti-CSRF Token",
                            JOptionPane.PLAIN_MESSAGE,
                            null,
                            null,
                            tokens.get(i));

                            if (s.trim().length() > 0)
                            {
                                tokens.set(i, s);
                            }
                        }
                    }
                });
                
                JButton removeToken = new JButton("Remove");
                removeToken.addActionListener(new ActionListener()
                {
                    @Override public void actionPerformed(ActionEvent e)
                    {
                        // Do it backwards so the indexes don't change!
                        int[] selectedIndices = tokenList.getSelectedIndices();
                        for (int i = selectedIndices.length -1; i >=0; i--)
                        {
                            tokens.remove(selectedIndices[i]);
                        }
                    }
                });
                
                addToken.setMinimumSize(removeToken.getMinimumSize());
                editToken.setMinimumSize(removeToken.getMinimumSize());
                
                caseSensitive = new JCheckBox("Case-sensitive token matching.");
                
                JLabel tokenAttributeLabel = new JLabel("Token Attribute Checks");
                tokenAttributeLabel.setFont(csrfListLabel.getFont());
                tokenAttributeLabel.setForeground(FONT_COLOR);
                
                tokenLengthCheck = new JCheckBox("Report instances when the anti-CSRF token value is less than");
                NumberFormat format = NumberFormat.getInstance();
                NumberFormatter formatter = new NumberFormatter(format);
                formatter.setValueClass(Integer.class);
                formatter.setMinimum(0);
                formatter.setMaximum(9999);
                formatter.setCommitsOnValidEdit(true);
                formatter.setAllowsInvalid(false);
                tokenLength = new JFormattedTextField(formatter);
                tokenLength.setValue(new Integer(0));
                tokenLength.setColumns(4);
                tokenLength.addPropertyChangeListener("value", new PropertyChangeListener()
                {
                    @Override public void propertyChange(PropertyChangeEvent evt)
                    {
                        minTokenLength = Integer.parseInt(tokenLength.getText());
                    }
                });
                
                tokenLength.setMaximumSize(new Dimension(50, 20));
                JLabel tokenLengthEnd = new JLabel("characters in length.");
                
                JLabel missingTokenLabel = new JLabel("Missing Token Checks");
                missingTokenLabel.setFont(csrfListLabel.getFont());
                missingTokenLabel.setForeground(FONT_COLOR);
                
                JLabel noTokenDesc = new JLabel("<html>Anti-CSRF tokens are generally found in request parameters "
                        + "and in HTML forms contained within the response. It is recommended that both are scanned "
                        + "to ensure all vulnerable requests / forms are identified.</html>");
                noTokenDesc.setPreferredSize(new Dimension(panel.getWidth(), 100));
                JLabel noTokenLabel = new JLabel("Passively scan and report when anti-CSRF tokens are not detected in:");
                noTokenRequests = new JCheckBox("Request Parameters (URL Query & HTTP Body)");
                noTokenForms = new JCheckBox("Response Forms");
                
                JLabel detectedTokenLabel = new JLabel("Detected Token Checks");
                detectedTokenLabel.setFont(csrfListLabel.getFont());
                detectedTokenLabel.setForeground(FONT_COLOR);
                JLabel foundTokenDesc = new JLabel("<html>Even if the application uses anti-CSRF tokens, they may not "
                + "have been implemented correctly or securely. For example, a request may still be successful "
                + "if the anti-CSRF token is modified or removed. It is important to perform manual tests on "
                + "these tokens for this reason, so knowing when they appear is also important. The following two "
                + "checks can help with this testing by reporting instances when anti-CSRF tokens appear.</html>");
                foundTokenDesc.setPreferredSize(new Dimension(panel.getWidth(), 100));
                
                JLabel foundTokenLabel = new JLabel("Passively scan and report when anti-CSRF tokens are detected in:");
                
                foundTokenRequests = new JCheckBox("Request Parameters (URL Query & HTTP Body)");
                foundTokenForms = new JCheckBox("Response Forms");
                
                JButton saveSettings = new JButton("Save Settings");
                saveSettings.addActionListener(new ActionListener()
                { 
                    @Override public void actionPerformed(ActionEvent e)
                    { 
                        saveConfig();
                    } 
                  });
                
                JButton restoreSettings = new JButton("Restore Saved Settings");
                restoreSettings.addActionListener(new ActionListener()
                { 
                    @Override public void actionPerformed(ActionEvent e)
                    { 
                        restoreConfig();
                    } 
                  });
                
                JButton restoreDefaults = new JButton("Restore Defaults");
                restoreDefaults.addActionListener(new ActionListener()
                { 
                    @Override public void actionPerformed(ActionEvent e)
                    { 
                        restoreDefaults();
                    } 
                  });
                
                GroupLayout layout = new GroupLayout(panel);
                panel.setLayout(layout);
                layout.setAutoCreateGaps(true);
                layout.setAutoCreateContainerGaps(true);
                
                layout.setHorizontalGroup(
                        layout.createSequentialGroup()
                        .addGap(15)
                        .addGroup(layout.createParallelGroup()
                        .addComponent(title)
                        .addComponent(desc)
                        .addComponent(csrfListLabel)
                        .addGroup(layout.createSequentialGroup()
                        .addComponent(scrollPane)
                        .addGroup(layout.createParallelGroup()
                        .addComponent(addToken)
                        .addComponent(editToken)
                        .addComponent(removeToken)))
                        .addComponent(caseSensitive)
                        
                        .addComponent(missingTokenLabel)
                        .addComponent(noTokenDesc)
                        .addComponent(noTokenLabel)
                        .addComponent(noTokenRequests)
                        .addComponent(noTokenForms)
                        .addComponent(detectedTokenLabel)
                        .addComponent(foundTokenDesc)
                        .addComponent(foundTokenLabel)
                        .addComponent(foundTokenRequests)
                        .addComponent(foundTokenForms)
                                
                        .addComponent(tokenAttributeLabel)
                        .addGroup(layout.createSequentialGroup()
                        .addComponent(tokenLengthCheck)
                        .addComponent(tokenLength)
                        .addComponent(tokenLengthEnd))
                                
                        .addGroup(layout.createSequentialGroup()
                        .addComponent(saveSettings)
                        .addComponent(restoreSettings)
                        .addComponent(restoreDefaults))));
                
                layout.setVerticalGroup(
                        layout.createSequentialGroup()
                        .addGap(15)
                        .addComponent(title)
                        .addComponent(desc)
                        .addGap(15)
                        .addComponent(csrfListLabel)
                        .addGroup(layout.createParallelGroup()
                        .addComponent(scrollPane)
                        .addGroup(layout.createSequentialGroup()
                        .addComponent(addToken)
                        .addComponent(editToken)
                        .addComponent(removeToken))) 
                        .addComponent(caseSensitive)
                        .addGap(15)
                        
                        .addComponent(missingTokenLabel)
                        .addComponent(noTokenDesc)
                        .addGap(10)
                        .addComponent(noTokenLabel)
                        .addComponent(noTokenRequests)
                        .addComponent(noTokenForms)
                        .addGap(20)
                        .addComponent(detectedTokenLabel)
                        .addComponent(foundTokenDesc)
                        .addGap(10)
                        .addComponent(foundTokenLabel)
                        .addComponent(foundTokenRequests)
                        .addComponent(foundTokenForms)
                        .addGap(20)
                        .addComponent(tokenAttributeLabel)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(tokenLengthCheck)
                        .addComponent(tokenLength)
                        .addComponent(tokenLengthEnd))
                        .addGap(30)
                        .addGroup(layout.createParallelGroup()
                        .addComponent(saveSettings)
                        .addComponent(restoreSettings)
                        .addComponent(restoreDefaults)));
                
                restoreConfig();
                
                // customize our UI components
                callbacks.customizeUiComponent(scroll);
                
                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }
    
    public void saveConfig()
    {
        this.callbacks.saveExtensionSetting("save", "1");
        
        this.callbacks.saveExtensionSetting("tokens", objectToString(tokens));
        
        this.callbacks.saveExtensionSetting("caseSensitive", Boolean.toString(caseSensitive.isSelected()));
        
        this.callbacks.saveExtensionSetting("tokenLengthCheck", Boolean.toString(tokenLengthCheck.isSelected()));
        this.callbacks.saveExtensionSetting("minTokenLength", Integer.toString(minTokenLength));
        
        this.callbacks.saveExtensionSetting("noTokenRequests", Boolean.toString(noTokenRequests.isSelected()));
        this.callbacks.saveExtensionSetting("noTokenForms", Boolean.toString(noTokenForms.isSelected()));
        
        this.callbacks.saveExtensionSetting("foundTokenRequests", Boolean.toString(foundTokenRequests.isSelected()));
        this.callbacks.saveExtensionSetting("foundTokenForms", Boolean.toString(foundTokenForms.isSelected()));
    }
    
    public void restoreConfig()
    {
        if (callbacks.loadExtensionSetting("save") == null || callbacks.loadExtensionSetting("save").equals("0"))
        {
            restoreDefaults();
        }
        else
        {
            if (this.callbacks.loadExtensionSetting("tokens") != null)
            {
                try
                {
                    tokens = (DefaultListModel<String>)stringToObject(this.callbacks.loadExtensionSetting("tokens"));
                }
                catch (ClassCastException e)
                {
                    tokens = new DefaultListModel<String>();
                    for (String s : DEFAULT_TOKEN_LIST)
                    {
                        tokens.addElement(s);
                    }
                }
            }
            else
            {
                tokens = new DefaultListModel<String>();
                for (String s : DEFAULT_TOKEN_LIST)
                {
                    tokens.addElement(s);
                }
            }
            tokenList.setModel(tokens);
            
            if (this.callbacks.loadExtensionSetting("caseSensitive") != null)
            {
                caseSensitive.setSelected(Boolean.parseBoolean(this.callbacks.loadExtensionSetting("caseSensitive")));
            }
            else
            {
                caseSensitive.setSelected(DEFAULT_CASE_INSENSITIVITY);
            }
            
            if (this.callbacks.loadExtensionSetting("tokenLengthCheck") != null)
            {
                tokenLengthCheck.setSelected(Boolean.parseBoolean(this.callbacks.loadExtensionSetting("tokenLengthCheck")));
            }
            else
            {
                tokenLengthCheck.setSelected(DEFAULT_MIN_TOKEN);
            }
            
            if (this.callbacks.loadExtensionSetting("minTokenLength") != null)
            {
                minTokenLength = Integer.parseInt(this.callbacks.loadExtensionSetting("minTokenLength"));
            }
            else
            {
                minTokenLength = DEFAULT_MIN_TOKEN_LENGTH;
            }
            tokenLength.setValue(minTokenLength);
            
            if (this.callbacks.loadExtensionSetting("noTokenRequests") != null)
            {
                noTokenRequests.setSelected(Boolean.parseBoolean(this.callbacks.loadExtensionSetting("noTokenRequests")));
            }
            else
            {
                noTokenRequests.setSelected(DEFAULT_NO_TOKEN_REQUESTS);
            }
            
            if (this.callbacks.loadExtensionSetting("noTokenForms") != null)
            {
                noTokenForms.setSelected(Boolean.parseBoolean(this.callbacks.loadExtensionSetting("noTokenForms")));
            }
            else
            {
                noTokenForms.setSelected(DEFAULT_NO_TOKEN_FORMS);
            }
            
            if (this.callbacks.loadExtensionSetting("foundTokenRequests") != null)
            {
                foundTokenRequests.setSelected(Boolean.parseBoolean(this.callbacks.loadExtensionSetting("foundTokenRequests")));
            }
            else
            {
                foundTokenRequests.setSelected(DEFAULT_FOUND_TOKEN_REQUESTS);
            }
            
            if (this.callbacks.loadExtensionSetting("foundTokenForms") != null)
            {
                foundTokenForms.setSelected(Boolean.parseBoolean(this.callbacks.loadExtensionSetting("foundTokenForms")));
            }
            else
            {
                foundTokenForms.setSelected(DEFAULT_FOUND_TOKEN_FORMS);
            }
        }
    }
    
    public void restoreDefaults()
    {
        this.callbacks.saveExtensionSetting("save", "2");
        
        tokens = new DefaultListModel<String>();
        for (String s : DEFAULT_TOKEN_LIST)
        {
            tokens.addElement(s);
        }
        tokenList.setModel(tokens);
        
        caseSensitive.setSelected(DEFAULT_CASE_INSENSITIVITY);
        
        tokenLengthCheck.setSelected(DEFAULT_MIN_TOKEN);
        tokenLength.setValue(DEFAULT_MIN_TOKEN_LENGTH);
        minTokenLength = DEFAULT_MIN_TOKEN_LENGTH;
        
        noTokenRequests.setSelected(DEFAULT_NO_TOKEN_REQUESTS);
        noTokenForms.setSelected(DEFAULT_NO_TOKEN_FORMS);
        
        foundTokenRequests.setSelected(DEFAULT_FOUND_TOKEN_REQUESTS);
        foundTokenForms.setSelected(DEFAULT_FOUND_TOKEN_FORMS);
    }
    
    public String objectToString(Object o)
    {
        try
        {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream out = new ObjectOutputStream(baos);
            out.writeObject(tokens);
            out.close();
            return base64Encoder.encode(baos.toByteArray());
        }
        catch (IOException e){}
        
        return "";
    }
    
    public Object stringToObject(String s)
    {
        try
        {
            byte [] data = base64Decoder.decodeBuffer(s);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object o  = ois.readObject();
            ois.close();
            return o;
        }
        catch (ClassNotFoundException e){}
        catch (IOException e){}
        
        return new Object();
    }
    
    @Override public String getTabCaption()
    {
        return "CSRF";
    }

    @Override public Component getUiComponent()
    {
        return scroll;
    }

    @Override public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        if (callbacks.isInScope(helpers.analyzeRequest(baseRequestResponse).getUrl()))
        {
            List<IScanIssue> issues = new ArrayList<IScanIssue>();
            List<int[]> noTokenRequestQueryHighlights = new ArrayList<int[]>(1);
            List<int[]> noTokenRequestHighlights = new ArrayList<int[]>(1);
            List<int[]> noTokenFormsHighlights = new ArrayList<int[]>(1);
            
            List<int[]> minRequestTokenLengthHighlights = new ArrayList<int[]>(1);
            List<int[]> minResponseTokenLengthHighlights = new ArrayList<int[]>(1);

            List<int[]> foundTokenRequestHighlights = new ArrayList<int[]>(1);
            List<int[]> foundTokenFormsHighlights = new ArrayList<int[]>(1);

            int requestOffset = helpers.analyzeResponse(baseRequestResponse.getRequest()).getBodyOffset();
            String requestBody = new String(baseRequestResponse.getRequest()).substring(requestOffset);

            int responseOffset = helpers.analyzeResponse(baseRequestResponse.getResponse()).getBodyOffset();
            String responseBody = new String(baseRequestResponse.getResponse()).substring(responseOffset);

            int start = 0, end = 0, next = 0;
            boolean token = false;
            String tokenValue = "";
            
            List<IParameter> params = helpers.analyzeRequest(baseRequestResponse).getParameters();
            if (!params.isEmpty())
            {
                boolean isUsableParam = false;
                for (IParameter param : params)
                {
                    if (param.getType() == IParameter.PARAM_BODY || param.getType() == IParameter.PARAM_URL)
                    {
                        isUsableParam = true;
                        break;
                    }
                }
                
                if (isUsableParam)
                {
                    for (IParameter param : params)
                    {
                        if (param.getType() == IParameter.PARAM_BODY || param.getType() == IParameter.PARAM_URL)
                        {
                            for (int i = 0; i < tokens.getSize(); i++)
                            {
                                if (caseSensitive.isSelected())
                                {
                                    if (tokens.get(i).equals(param.getName()))
                                    {
                                        token = true;
                                        tokenValue = param.getValue();
                                        start = param.getNameStart();
                                        end = param.getValueEnd();
                                        break;
                                    }
                                }
                                else
                                {
                                    if (tokens.get(i).equalsIgnoreCase(param.getName()))
                                    {
                                        token = true;
                                        tokenValue = param.getValue();
                                        start = param.getNameStart();
                                        end = param.getValueEnd();
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if (!token)
                    {
                        if (noTokenRequests.isSelected())
                        {
                            String query = helpers.analyzeRequest(baseRequestResponse).getUrl().getQuery();
                            if (query != null)
                            {
                                int queryStart = new String(baseRequestResponse.getRequest()).indexOf(query);
                                noTokenRequestQueryHighlights.add(new int[] {queryStart, queryStart + query.length()});
                            }
                            noTokenRequestHighlights.add(new int[] {requestOffset, requestOffset + requestBody.length()});
                        }
                    }
                    else
                    {
                        if (foundTokenRequests.isSelected())
                        {
                            foundTokenRequestHighlights.add(new int[] {start, end});
                        }

                        if (tokenLengthCheck.isSelected())
                        {    
                            try
                            {
                                if (URLDecoder.decode(tokenValue, "UTF-8").length() < minTokenLength)
                                {
                                    minRequestTokenLengthHighlights.add(new int[] {start, end});
                                }
                            }
                            catch (UnsupportedEncodingException e){}
                        }
                    }
                }
            }

            // Check Responses for Forms
            start = 0;
            end = 0;
            next = 0;
            
            FORM_OPEN_MATCHER.reset(responseBody);
            FORM_CLOSE_MATCHER.reset(responseBody);
            
            while (FORM_OPEN_MATCHER.find())
            {
                start = responseBody.indexOf(FORM_OPEN_MATCHER.group(), next);
                next = start;
                
                if (FORM_CLOSE_MATCHER.find())
                {
                    end = responseBody.indexOf(FORM_CLOSE_MATCHER.group(), next) + FORM_CLOSE_MATCHER.group().length();
                    next = end;
                    
                    Document doc = Jsoup.parse("<html><head></head><body>" + responseBody.substring(start, end) + "</body></html>");
                    token = false;
                    tokenValue = "";
                    Elements inputs = doc.select("input");
                    for (Element input : inputs)
                    {
                        if (input.hasAttr("name"))
                        {
                            for (int i = 0; i < tokens.getSize(); i++)
                            {
                                if (caseSensitive.isSelected())
                                {
                                    if (tokens.get(i).equals(input.attr("name")))
                                    {
                                        token = true;
                                        tokenValue = input.val();
                                        break;
                                    }
                                }
                                else
                                {
                                    if (tokens.get(i).equalsIgnoreCase(input.attr("name")))
                                    {
                                        token = true;
                                        tokenValue = input.val();
                                        break;
                                    }
                                }
                            }
                            
                            if (token)
                            {
                                break;
                            }
                        }
                    }
                    
                    if (!token)
                    {
                        if (noTokenForms.isSelected())
                        {
                            noTokenFormsHighlights.add(new int[] {responseOffset + start, responseOffset + end});
                        }
                    }
                    else
                    {
                        if (foundTokenForms.isSelected())
                        {
                            foundTokenFormsHighlights.add(new int[] {responseOffset + start, responseOffset + end});
                        }

                        if (tokenLengthCheck.isSelected())
                        {
                            if (tokenValue.length() < minTokenLength)
                            {
                                minResponseTokenLengthHighlights.add(new int[] {responseOffset + start, responseOffset + end});
                            }
                        }
                    }
                }
            }

            if (!noTokenRequestQueryHighlights.isEmpty() && !noTokenRequestHighlights.isEmpty())
            {
                noTokenRequestQueryHighlights.addAll(noTokenRequestHighlights);
                
                issues.add(new CSRFScanIssue(
                        NO_TOKEN_IN_REQUEST_PARAMS,
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, noTokenRequestQueryHighlights, null)},
                        "High",
                        "Tentative",
                        "The request parameters do not appear to contain an anti-CSRF token."
                    ));
            }
            else
            {
                if (!noTokenRequestQueryHighlights.isEmpty())
                {
                    issues.add(new CSRFScanIssue(
                        NO_TOKEN_IN_REQUEST_PARAMS,
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                        new IHttpRequestResponse[] {callbacks.applyMarkers(baseRequestResponse, noTokenRequestQueryHighlights, null)},
                        "High",
                        "Tentative",
                        "The request URL parameters do not appear to contain an anti-CSRF token."
                    ));
                }

                if (!noTokenRequestHighlights.isEmpty())
                {
                    issues.add(new CSRFScanIssue(
                        NO_TOKEN_IN_REQUEST_PARAMS,
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                        new IHttpRequestResponse[] {callbacks.applyMarkers(baseRequestResponse, noTokenRequestHighlights, null)},
                        "High",
                        "Tentative",
                        "The request body parameters do not appear to contain an anti-CSRF token."
                    ));
                }
            }
            
            if (!foundTokenRequestHighlights.isEmpty())
            {
                issues.add(new CSRFScanIssue(
                    TOKEN_IN_REQUEST_PARAMS,
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, foundTokenRequestHighlights, null)},
                    "Information",
                    "Firm",
                    "The request parameters appear to contain an anti-CSRF token. It is suggested that the request "
                        + "be replayed both without and with a modified token to see if it is implemented properly."
                ));
            }
            
            if (!minRequestTokenLengthHighlights.isEmpty())
            {
                issues.add(new CSRFScanIssue(
                    SHORT_TOKEN,
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, minRequestTokenLengthHighlights, null)},
                    "Medium",
                    "Firm",
                    "The request parameters appear to contain an anti-CSRF token with a value that is "
                        + "less than " + minTokenLength + " characters long. An attacker may be able to guess "
                        + "this token's value."
                ));
            }
            
            if (!minResponseTokenLengthHighlights.isEmpty())
            {
                String detail;
                if (minResponseTokenLengthHighlights.size() > 1)
                {
                    detail = "The response contains " + minResponseTokenLengthHighlights.size() + " forms which appear to "
                            + "contain an anti-CSRF token with a value that is less than " + minTokenLength
                            + " characters long. An attacker may be able to guess this token's value.";
                }
                else
                {
                    detail = "The response contains a form which appears to contain an anti-CSRF token with a "
                            + "value that is less than " + minTokenLength + " characters long. An attacker may "
                            + "be able to guess this token's value.";
                }
                
                issues.add(new CSRFScanIssue(
                    SHORT_TOKEN,
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, minResponseTokenLengthHighlights)},
                    "Medium",
                    "Firm",
                    detail
                ));
            }

            if (!noTokenFormsHighlights.isEmpty())
            {
                String detail = "";
                if (noTokenFormsHighlights.size() > 1)
                {
                    detail = "The response contains " + noTokenFormsHighlights.size() + " forms which do not appear to contain an anti-CSRF token.";
                }
                else
                {
                    detail = "The response contains a form which does not appear to contain an anti-CSRF token.";
                }

                issues.add(new CSRFScanIssue(
                    NO_TOKEN_IN_RESPONSE_FORM,
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, noTokenFormsHighlights)},
                    "High",
                    "Tentative",
                    detail
                ));
            }
            
            if (!foundTokenFormsHighlights.isEmpty())
            {
                String detail = "";
                if (foundTokenFormsHighlights.size() > 1)
                {
                    detail = "The response contains " + foundTokenFormsHighlights.size() + " forms which appear to "
                            + "contain an anti-CSRF token. It is suggested that the forms be submitted both without "
                            + "and with a modified token to see if it is implemented properly.";
                }
                else
                {
                    detail = "The response contains a form which appears to contain an anti-CSRF token. It is "
                            + "suggested that the form be submitted both without and with a modified token to "
                            + "see if it is implemented properly.";
                }

                issues.add(new CSRFScanIssue(
                    TOKEN_IN_RESPONSE_FORM,
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, foundTokenFormsHighlights)},
                    "Information",
                    "Firm",
                    detail
                ));
            }

            if (!issues.isEmpty())
            {
                return issues;
            }
        }
        
        return null;
    }

    @Override public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        return null;
    }

    @Override public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        final int DO_NOT_ADD_NEW_ISSUE = -1;
        final int ADD_NEW_ISSUE = 0;
        
        if (newIssue.getIssueName().equals(existingIssue.getIssueName()))
        {
            
            if (helpers.analyzeRequest(newIssue.getHttpMessages()[0]).getUrl().getPath().equals(helpers.analyzeRequest(existingIssue.getHttpMessages()[0]).getUrl().getPath()))
            {
                List<IParameter> originalNewParams = helpers.analyzeRequest(newIssue.getHttpMessages()[0]).getParameters();
                List<IParameter> originalExistingParams = helpers.analyzeRequest(existingIssue.getHttpMessages()[0]).getParameters();

                // Rebuild parameter lists.
                List<IParameter> newParams = new LinkedList<IParameter>();
                for (IParameter param : originalNewParams)
                {
                    if (param.getType() == IParameter.PARAM_BODY || param.getType() == IParameter.PARAM_URL)
                    {
                        if (newIssue.getIssueName().equals(TOKEN_IN_REQUEST_PARAMS)) // Prevents duplicate tokens being reported.
                        {
                            boolean token = false;
                            
                            for (int i = 0; i < tokens.getSize(); i++)
                            {
                                if (caseSensitive.isSelected())
                                {
                                    if (tokens.get(i).equals(param.getName()))
                                    {
                                        token = true;
                                        break;
                                    }
                                }
                                else
                                {
                                    if (tokens.get(i).equalsIgnoreCase(param.getName()))
                                    {
                                        token = true;
                                        break;
                                    }
                                }
                            }
                            
                            if (!token)
                            {
                                newParams.add(param);
                            }
                        }
                        else
                        {
                            newParams.add(param);
                        }
                    }
                }
                
                List<IParameter> existingParams = new LinkedList<IParameter>();
                for (IParameter param : originalExistingParams)
                {
                    if (param.getType() == IParameter.PARAM_BODY || param.getType() == IParameter.PARAM_URL)
                    {
                        if (existingIssue.getIssueName().equals(TOKEN_IN_REQUEST_PARAMS)) // Prevents duplicate tokens being reported.
                        {
                            boolean token = false;
                            
                            for (int i = 0; i < tokens.getSize(); i++)
                            {
                                if (caseSensitive.isSelected())
                                {
                                    if (tokens.get(i).equals(param.getName()))
                                    {
                                        token = true;
                                        break;
                                    }
                                }
                                else
                                {
                                    if (tokens.get(i).equalsIgnoreCase(param.getName()))
                                    {
                                        token = true;
                                        break;
                                    }
                                }
                            }
                            
                            if (!token)
                            {
                                existingParams.add(param);
                            }
                        }
                        else
                        {
                            existingParams.add(param);
                        }
                    }
                }
                
                if (newParams.size() == existingParams.size())
                {
                    if (newParams.isEmpty())
                    {
                        return DO_NOT_ADD_NEW_ISSUE;
                    }
                    else
                    {
                        for (IParameter newParam : newParams)
                        {
                            boolean paramsMatch = false;
                            
                            for (IParameter existingParam : existingParams)
                            {
                                if (newParam.getName().equals(existingParam.getName()) && newParam.getValue().equals(existingParam.getValue()))
                                {
                                    paramsMatch = true;
                                    break;
                                }
                            }
                            
                            if (paramsMatch == false)
                            {
                                return ADD_NEW_ISSUE;
                            }
                        }
                        
                        return DO_NOT_ADD_NEW_ISSUE;
                    }
                }
                else
                {
                    return ADD_NEW_ISSUE;
                }
            }
            else // If the new issue has a different path to the existing issue, it should be added.
            {
                return ADD_NEW_ISSUE;
            }
        }
        else // If the new issue has a different name to the existing issue, it should be added.
        {
            return ADD_NEW_ISSUE;
        }
    }
    
    class CSRFScanIssue implements IScanIssue
    {
        private String name, severity, confidence, detail;
        private IHttpService httpService;
        private URL url;
        private IHttpRequestResponse[] httpMessages;
        
        public CSRFScanIssue(String name, IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String severity, String confidence, String detail)
        {
            this.name = name;
            this.httpService = httpService;
            this.url = url;
            this.httpMessages = httpMessages;
            this.severity = severity;
            this.confidence = confidence;
            this.detail = detail;
        }
        
        @Override public URL getUrl()
        {
            return url;
        }

        @Override public String getIssueName()
        {
            return name;
        }

        @Override public int getIssueType()
        {
            return 0;
        }

        @Override public String getSeverity()
        {
            return severity;
        }

        @Override public String getConfidence()
        {
            return confidence;
        }

        @Override public String getIssueBackground()
        {
            return "Cross-site Request Forgery (CSRF) is an attack which forces an end user to execute "
                    + "unwanted actions on a web application to which he/she is currently authenticated. "
                    + "With a little help of social engineering (like sending a link via email / chat), "
                    + "an attacker may trick the users of a web application into executing actions of the "
                    + "attacker's choosing. A successful CSRF exploit can compromise end user data and may "
                    + "allow an attacker to perform an account hijack. If the targeted end user is the "
                    + "administrator account, this can compromise the entire web application.";
        }

        @Override public String getRemediationBackground()
        {
            return "The application should implement anti-CSRF tokens into all requests that perform "
                    + " actions which change the application state or which add/modify/delete content. "
                    + "An anti-CSRF token should be a long randomly generated value unique to each user so "
                    + "that attackers cannot easily brute-force it.<br><br>It is important that anti-CSRF tokens "
                    + "are validated when user requests are handled by the application. The application should "
                    + "both verify that the token exists in the request, and also check that it matches the user's current "
                    + "token. If either of these checks fails, the application should reject the request.";
        }

        @Override public String getIssueDetail()
        {
            return detail;
        }

        @Override public String getRemediationDetail()
        {
            return null;
        }

        @Override public IHttpRequestResponse[] getHttpMessages()
        {
            return httpMessages;
        }

        @Override public IHttpService getHttpService()
        {
            return httpService;
        }
        
    }
}