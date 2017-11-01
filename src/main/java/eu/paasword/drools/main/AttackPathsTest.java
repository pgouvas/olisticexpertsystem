package eu.paasword.drools.main;

import eu.paasword.drools.risk.Asset;
import eu.paasword.drools.risk.Attacker;
import eu.paasword.drools.risk.Dependency;
import eu.paasword.drools.risk.ExceptionStructural;
import eu.paasword.drools.risk.Path;
import eu.paasword.drools.risk.Vulnerability;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import org.kie.api.KieServices;
import org.kie.api.runtime.KieContainer;
import org.kie.api.runtime.KieSession;
import org.kie.api.runtime.ObjectFilter;
import org.kie.api.runtime.rule.FactHandle;

public class AttackPathsTest {

    private static final Logger logger = Logger.getLogger(AttackPathsTest.class.getName());

    public static void main(String[] args) {

        // load up the knowledge base
        KieServices ks = KieServices.Factory.get();
        KieContainer kcontainer = ks.getKieClasspathContainer();
        KieSession ksession = kcontainer.newKieSession("ksession-rules");

        //Environment Setup
        //0-hardware  1-OS   2-App
        Asset a1 = new Asset("joomla", 2);
        Asset a2 = new Asset("os1", 1);
        Asset a3 = new Asset("os2", 1);
        Asset a4 = new Asset("os3", 1);
        Asset a5 = new Asset("webapp", 2);
        Asset a6 = new Asset("database", 2);
        Asset a7 = new Asset("mailserver", 2);

        //access vector 0-Local  1-Adjacent  2-Network
        //access complexity 0-Low  1-Medium  2-High
        //authentication 0-None  1-SingleFactor  2-MultipleFactor        
        Vulnerability v1 = new Vulnerability("v1", 2, 0, 0);            //Remotely exploited - Low Complexity - None Authentication       
        Vulnerability v2 = new Vulnerability("v2", 0, 0, 0);            //Localy exploited - Low Complexity - None Authentication       
        Vulnerability v3 = new Vulnerability("v3", 2, 2, 0);            //Remotely exploited - High Complexity - None Authentication       
        Vulnerability v4 = new Vulnerability("v4", 0, 2, 0);            //Locally exploited - High Complexity - None Authentication       

        a1.addVulnerability(v1);
        a2.addVulnerability(v2);
        a2.addVulnerability(v4);
        a3.addVulnerability(v1);
        a6.addVulnerability(v2);
        a7.addVulnerability(v2);

        //Dependencies
        // 0-IsInstalledOn  1-NetworkConnected
        Dependency d1 = new Dependency("joomla", "os1", 0);
        Dependency d2 = new Dependency("mailserver", "os1", 0);
        Dependency d3 = new Dependency("os1", "os2", 1);
        Dependency d4 = new Dependency("os1", "os3", 1);
        Dependency d5 = new Dependency("os2", "os3", 1);
        Dependency d6 = new Dependency("database", "os2", 1);
        Dependency d7 = new Dependency("webapp", "os3", 1);
        Dependency d8 = new Dependency("webapp", "db", 0);

        //Skill
        //0-Low  1-Medium  2-High  
        Attacker at1 = new Attacker("a1", 2);

        //final setup
        a1.setIsentrypoint(true);
        a7.setIsentrypoint(true);
        a6.setIstarget(true);

        //load facts
        ksession.insert(a1);//assets
        ksession.insert(a2);
        ksession.insert(a3);
        ksession.insert(a4);
        ksession.insert(a5);
        ksession.insert(a6);
        ksession.insert(a7);
        ksession.insert(v1);//vulns
        ksession.insert(v2);
        ksession.insert(v3);
        ksession.insert(v4);
        ksession.insert(d1);//Relationships
        ksession.insert(d2);
        ksession.insert(d3);
        ksession.insert(d4);
        ksession.insert(d5);
        ksession.insert(d6);
        ksession.insert(d7);
        ksession.insert(d8);
        ksession.insert(at1);//attacker profile

        //fire
        ksession.fireAllRules();

        //iterate results
        boolean errorduringexecution = false;
        Map<String, Map<String, String>> edges = new HashMap<>();         //<String,Map<String,String>> = Map<fromnode,Map<vuln,tonone>> 

        for (FactHandle handle : ksession.getFactHandles(new ObjectFilter() {
            public boolean accept(Object object) {
                if (ExceptionStructural.class.equals(object.getClass())) {
                    return true;
                }
                if (Path.class.equals(object.getClass())) {
                    return true;
                }
                return false;
            }
        })) {//for body
            Object obj = ksession.getObject(handle);
            if (obj instanceof ExceptionStructural) {
                errorduringexecution = true;
                logger.info("Error during execution");
                break;
            } else if (obj instanceof Path) {
                Path path = (Path) obj;
                Map<String, String> values;
                if (edges.get(path.getFrom()) != null) {
                    values = edges.get(path.getFrom());
                } else {
                    values = new HashMap<>();
                }
                values.put(path.getVuln(), path.getTo());
                edges.put(path.getFrom(), values);
            }
        }//for
        
        logger.info(edges.toString());
        
    }//EoM

    private void constructPathsFromEntryPoint(String entrypoint, Map<String, Map<String, String>> edges){
        
                
    }
    
    private void constructPathsToTargetPoint(){
        
    }
    
    
}//EoC
