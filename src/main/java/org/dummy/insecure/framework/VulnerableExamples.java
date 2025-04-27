package org.dummy.insecure.framework;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;

import java.util.HashMap;
import java.util.Map;


public class VulnerableExamples {
    
    private static final Logger logger = Logger.getLogger(VulnerableExamples.class);
    
    // Vulnerable Jackson usage example
    public String parseJson(String input) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            // Enable default typing which is vulnerable in this version
            mapper.enableDefaultTyping();
            
            Object obj = mapper.readValue(input, Object.class);
            return mapper.writeValueAsString(obj);
        } catch (Exception e) {
            logger.error("Error parsing JSON", e);
            return null;
        }
    }
    
    // Vulnerable Commons Collections usage example
    public void vulnerableCollectionsExample() {
        Transformer[] transformers = new Transformer[] {
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", 
                new Class[] {String.class, Class[].class}, 
                new Object[] {"getRuntime", new Class[0]}),
            new InvokerTransformer("invoke", 
                new Class[] {Object.class, Object[].class}, 
                new Object[] {null, new Object[0]}),
            new InvokerTransformer("exec", 
                new Class[] {String.class}, 
                new Object[] {"echo 'Just for demonstration'"})
        };
        
        Transformer transformerChain = new ChainedTransformer(transformers);
        
        Map<String, String> tempMap = new HashMap<String, String>();
        tempMap.put("key", "value");
        
        // Create TransformedMap with the vulnerable transformer chain
        Map<String, String> vulnerableMap = TransformedMap.decorate(tempMap, null, transformerChain);
        
        // This code is intentionally commented out as it would actually execute the command
        // In a real exploit, this could be triggered through deserialization
        /*
        try {
            Map.Entry entry = (Map.Entry) vulnerableMap.entrySet().iterator().next();
            entry.setValue("anything");
        } catch (Exception e) {
            logger.error("Error in collections example", e);
        }
        */
    }
    
    // Vulnerable Struts2 usage example
    public void strutsExample(String userInput) {
        // Using a vulnerable Struts2 pattern
        // This is just demonstrating the import and usage, not actual exploitation
        try {
            String result = ServletActionContext.getRequest().getParameter(userInput);
            logger.info("Struts2 result: " + result);
        } catch (Exception e) {
            logger.error("Error in Struts example", e);
        }
    }
    
    // Main method to demonstrate usage
    public static void main(String[] args) {
        VulnerableExamples examples = new VulnerableExamples();
        
        // Log something with vulnerable log4j
        logger.info("Testing vulnerable dependencies");
        
        // Call the methods to ensure dependencies are used
        examples.parseJson("{\"key\":\"value\"}");
        examples.vulnerableCollectionsExample();
        examples.strutsExample("testParam");
        
        logger.info("Vulnerability demonstrations completed");
    }
}