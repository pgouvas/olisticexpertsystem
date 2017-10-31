package eu.paasword.drools.main;

import eu.paasword.drools.risk.Asset;
import eu.paasword.drools.risk.Attacker;
import eu.paasword.drools.risk.Dependency;
import eu.paasword.drools.risk.Vulnerability;
import org.kie.api.KieServices;
import org.kie.api.runtime.KieContainer;
import org.kie.api.runtime.KieSession;

public class AttackPathsTest {

    public static void main(String[] args) {
            // load up the knowledge base
            KieServices ks = KieServices.Factory.get();
            KieContainer kcontainer = ks.getKieClasspathContainer();
            KieSession ksession = kcontainer.newKieSession("ksession-rules");
            
            //Environment Setup
            //0-hardware  1-OS   2-App
            Asset a1 = new Asset("a1",0);               
            Asset a2 = new Asset("a2",0);
            Asset a3 = new Asset("a3",0);
            Asset a4 = new Asset("a4",0);

            //access vector 0-Local  1-Adjacent  2-Network
            //access complexity 0-Low  1-Medium  2-Heigh
            //authentication 0-None  1-SingleFactor  2-MultipleFactor        
            Vulnerability v1 = new Vulnerability("v1", 2, 0, 0);            
            
            a1.addVulnerability(v1);
            
            //Dependencies
            //authentication 0-None  1-SingleFactor  2-MultipleFactor
            Dependency d1 = new Dependency("1","2",0);
            Dependency d2 = new Dependency("1","3",0);
            Dependency d3 = new Dependency("2","4",0);
            Dependency d4 = new Dependency("3","4",0);
            
            //0-Low  1-Medium  2-High  
            Attacker at1 = new Attacker("a1",1);
            
            //final setup
            a1.setIsentrypoint(true);
            a4.setIstarget(true);            
            
            //fire
            ksession.fireAllRules();
            
            
    }//EoM
    
}//EoC
