package eu.paasword.drools.main;

import eu.paasword.drools.risk.Asset;
import eu.paasword.drools.risk.Attacker;
import eu.paasword.drools.risk.Chain;
import eu.paasword.drools.risk.Dependency;
import eu.paasword.drools.risk.ExceptionStructural;
import eu.paasword.drools.risk.Path;
import eu.paasword.drools.risk.Vulnerability;
import static java.lang.Double.max;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import org.kie.api.KieServices;
import org.kie.api.runtime.KieContainer;
import org.kie.api.runtime.KieSession;
import org.kie.api.runtime.ObjectFilter;
import org.kie.api.runtime.rule.FactHandle;
import java.util.concurrent.ThreadLocalRandom;

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
        a6.addVulnerability(v1);
        a7.addVulnerability(v2);
        a7.addVulnerability(v1);

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
        Dependency d9 = new Dependency("os2", "joomla", 1);

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
        ksession.insert(d9);
        ksession.insert(at1);//attacker profile

//////////////////----Scaling test
        int assetmax = 4000;
        int vulnsmax = 10;
        int vulnspernode = 4;
        int deppernode = 2;
        List<Asset> labassets = new ArrayList<>();
        List<Vulnerability> labvulns = new ArrayList<>();
        List<Dependency> labdeps = new ArrayList<>();

        for (int i = 0; i < assetmax; i++) {
            Asset as = new Asset("as" + i, 2);
            labassets.add(as);
        }//for           

        for (int i = 0; i < vulnsmax; i++) {
            Vulnerability vuln = new Vulnerability("v" + i, 2, 0, 0);
            labvulns.add(vuln);
        }//for           

        for (int i = 0; i < assetmax; i++) {
            Asset as = labassets.get(i);

            for (int v = 0; v < vulnspernode; v++) {
                int randomNum0 = ThreadLocalRandom.current().nextInt(0, vulnsmax - 1);
                as.addVulnerability(labvulns.get(randomNum0));
            }

            for (int j = 0; j < deppernode; j++) {
                int randomNum = ThreadLocalRandom.current().nextInt(0, assetmax-1);
                if (i != randomNum) {
                    Dependency dep = new Dependency(as.getId(), labassets.get(randomNum).getId(), 1);
                    labdeps.add(dep);
                }
            }//for
        }//for        

        labassets.stream().forEach(t -> ksession.insert(t));
        labvulns.stream().forEach(t -> ksession.insert(t));
        labdeps.stream().forEach(t -> ksession.insert(t));

        labassets.get(0).setIsentrypoint(true);
        //labassets.get(1).setIsentrypoint(true);

////////////////////////////////////
        //fire
        long startTime = System.currentTimeMillis();
        
        ksession.fireAllRules();

        long stopTime = System.currentTimeMillis();
        long elapsedTime = stopTime - startTime;
        System.out.println("Reasoning Engine (Path Identification): " + elapsedTime);

        startTime = System.currentTimeMillis();

        //iterate results
        boolean errorduringexecution = false;
        int chaincount=0;
        int pathcount=0;
        Map<String, List<Map<String, List<String>>>> edges = new HashMap<>();         //<String, Map<String,String>{0} Map<String,String>{1} > = Map<fromnode, Map<vuln,tonone> Map<tonode,vuln>{1}   > 

        for (FactHandle handle : ksession.getFactHandles(new ObjectFilter() {
            public boolean accept(Object object) {
                if (ExceptionStructural.class.equals(object.getClass())) {
                    return true;
                }
                if (Path.class.equals(object.getClass())) {
                    return true;
                }
                if (Chain.class.equals(object.getClass())) {
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
                pathcount++;
                String from = path.getFrom();
                String target = path.getTo();
                String vuln = path.getVuln();
                //System.out.println("Path: "+from+" -> "+target+" ("+vuln+")");
                List<Map<String, List<String>>> edgelist;
                Map<String, List<String>> vulnmap;
                Map<String, List<String>> targetmap;

                if (edges.get(from) == null) {
                    edgelist = new ArrayList<>();
                    vulnmap = new HashMap<>();
                    targetmap = new HashMap<>();
                    edgelist.add(vulnmap);
                    edgelist.add(targetmap);
                } else {
                    edgelist = edges.get(from);
                    vulnmap = edges.get(path.getFrom()).get(0);
                    targetmap = edges.get(path.getFrom()).get(1);
                }
                edges.put(from, edgelist);

                //vuln index
                if (vulnmap.get(vuln) == null) {
                    List<String> vulnlist = new ArrayList<>();
                    vulnlist.add(target);
                    vulnmap.put(vuln, vulnlist);
                } else if (!vulnmap.get(vuln).contains(target)) {
                    vulnmap.get(vuln).add(target);
                }

                //target index
                if (targetmap.get(target) == null) {
                    List<String> targetlist = new ArrayList<>();
                    targetlist.add(vuln);
                    targetmap.put(target, targetlist);
                } else if (!targetmap.get(target).contains(vuln)) {
                    targetmap.get(target).add(vuln);
                }

//                edges.put(path.getFrom(), vulnmap);
            } else if (obj instanceof Chain){           //END PATH
                Chain chain = (Chain)obj;
                chaincount++;
//                System.out.println( chain.print() );
            }
        }//for

        stopTime = System.currentTimeMillis();
        elapsedTime = stopTime - startTime;
        System.out.println("Path & Chain Indexing: " + elapsedTime);
        System.out.println("#Paths : " + pathcount );
        System.out.println("#Chains: " + chaincount);

//        if (!errorduringexecution) {
//            logger.info(edges.toString());
//            startTime = System.currentTimeMillis();
//            
//            constructPathsFromEntryPoint("RemoteAdversary", edges);
//            
//            stopTime = System.currentTimeMillis();
//            elapsedTime = stopTime - startTime;
//            System.out.println("Chain Serialization: " + elapsedTime);
//        }//if

    }//EoM

    private static void constructPathsFromEntryPoint(String entrypoint, Map<String, List<Map<String, List<String>>>> edges) {
//        System.out.println("Exploring " + entrypoint);
        Map<String, List<String>> targets = edges.get(entrypoint).get(1);
        String path = entrypoint + "-> ";
        
        for (Map.Entry<String, List<String>> entry : targets.entrySet()) {
            String target = entry.getKey();
            List<String> vulnlist = entry.getValue();
            for (String vuln : vulnlist) {
                explorePathsFromNode(target, vuln, path, edges);
            }//for
        }//for        
    }//EoM

    private static void explorePathsFromNode(String node, String vul, String path, Map<String, List<Map<String, List<String>>>> edges) {
//        System.out.println("Exploring " + node + " from path " + path);
        path += node + "(" + vul + ") -> ";
        System.out.println("Chain:" + path);

        if (edges.get(node) == null) {
//            System.out.println("end of recursion for node <" + node + "> using path:" + path);
        } else {
            Map<String, List<String>> targets = edges.get(node).get(1);
            for (Map.Entry<String, List<String>> entry : targets.entrySet()) {
                String target = entry.getKey();
                List<String> vulnlist = entry.getValue();
                for (String vuln : vulnlist) {
                    explorePathsFromNode(target, vuln, path, edges);
                }
            }//for                 
        }//for             
    }//EoM

    private void constructPathsToTargetPoint() {

    }//EoM

}//EoC
