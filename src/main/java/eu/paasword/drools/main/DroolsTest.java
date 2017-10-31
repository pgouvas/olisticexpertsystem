package eu.paasword.drools.main;

import eu.paasword.drools.Clazz;
import eu.paasword.drools.InstanceOfClazz;
import eu.paasword.drools.KnowledgeTriple;
import eu.paasword.drools.LogicalError;
import eu.paasword.drools.ObjectProperty;
import eu.paasword.drools.util.ReflectionUtil;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.kie.api.KieServices;
import org.kie.api.runtime.KieContainer;
import org.kie.api.runtime.KieSession;
import org.kie.api.runtime.ObjectFilter;
import org.kie.api.runtime.rule.AgendaFilter;
import org.kie.api.runtime.rule.FactHandle;
import org.kie.api.runtime.rule.Match;

/**
 * This is a sample class to launch a rule.
 */
public class DroolsTest {

    private static final Logger logger = Logger.getLogger(DroolsTest.class.getName());

    private String ontologypath = "/media/ubuntu/disk21/workspace/olisticexpertsystem/src/main/resources/ontology/ontology.onto";

    public static final void main(String[] args) {
        DroolsTest droolstest = new DroolsTest();
        droolstest.run();
    }//EoM

    public void run() {
        try {

            // load up the knowledge base
            KieServices ks = KieServices.Factory.get();
            KieContainer kcontainer = ks.getKieClasspathContainer();
            KieSession ksession = kcontainer.newKieSession("ksession-rules");

            //load the ontology
            loadOntology(ksession);

            //fire Rules
            logger.info("Fire!");
            ksession.fireAllRules();

            logger.info("Fire 2");
            //FactHandle f1 = (FactHandle) getObjectFromAgenda(ksession, Clazz.class, "Database");
            //Clazz cl1 = (Clazz) ksession.getObject(f1);            
            
            
            logger.info("Fire!");
            ksession.fireAllRules();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }//EoM

    public static Object getObjectFromAgenda(KieSession ksession, Class cl, String objectname) {
        Object obj = null;

        Collection<FactHandle> factHandles = ksession.getFactHandles(new ObjectFilter() {
            public boolean accept(Object object) {
                if (object.getClass().equals(cl) && ReflectionUtil.getNameOfObject(object).equalsIgnoreCase(objectname)) {
                    return true;
                }
                return false;
            }
        });
        logger.info("Query for " + objectname + "(" + cl.getName() + ") returned: " + factHandles.size());
        if (!factHandles.isEmpty()) {
            return factHandles.iterator().next();
        }
        return obj;
    }//EoM

    public KieSession loadOntology(KieSession ksession) {
        Map<String, Object> intiorphanclassobjectmap = new HashMap<>();
        Map<String, Object> intermediateclassobjectmap = new HashMap<>();
        Map<String, Object> finalclassobjectmap = new HashMap<>();
        Map<String, Object> finalinstanceobjectmap = new HashMap<>();
        Map<String, Object> initopobjectmap = new HashMap<>();
        Map<String, Object> intermediateopobjectmap = new HashMap<>();
        Map<String, Object> finalopobjectmap = new HashMap<>();
        List<Object> finalktriplesobjectlist = new ArrayList<>();

        try {
            /*
            *   LOAD CLASSES
             */
            //Fetch all Classes that are orphan
            Stream<String> stream = Files.lines(Paths.get(ontologypath));
            intiorphanclassobjectmap = stream
                    .filter(line -> !line.startsWith("#") && !line.trim().equalsIgnoreCase("") && ((line.split(",")[0]).trim().equalsIgnoreCase("C") || (line.split(",")[0]).trim().equalsIgnoreCase("Class"))) //&& (line.split(",")[2]).trim().equalsIgnoreCase("null")
                    .map(line -> ReflectionUtil.createOrphanClazz(ReflectionUtil.getClassLabelFromLine(line)))
                    .collect(Collectors.toMap(o -> ReflectionUtil.getNameOfObject(o), o -> o));
            final Map<String, Object> temp1 = intiorphanclassobjectmap;
//            logger.info("1st Pass of Classes: ");
//            intiorphanclassobjectmap.values().forEach(System.out::println);

            //Handle Non Orphan
            Stream<String> stream2 = Files.lines(Paths.get(ontologypath));
            intermediateclassobjectmap = stream2
                    .filter(line -> !line.startsWith("#") && !line.trim().equalsIgnoreCase("") && ((line.split(",")[0]).trim().equalsIgnoreCase("C") || (line.split(",")[0]).trim().equalsIgnoreCase("Class")) && !(line.split(",")[2]).trim().equalsIgnoreCase("null"))
                    .map(line -> ReflectionUtil.setParentToClazzObject(temp1.get(ReflectionUtil.getClassLabelFromLine(line)), temp1.get(ReflectionUtil.getParentalClassLabelFromLine(line))))
                    .collect(Collectors.toMap(o -> ReflectionUtil.getNameOfObject(o), o -> o));

            final Map<String, Object> temp2 = intermediateclassobjectmap;
//            logger.info("Intermediate Pass of Classes: ");
//            intermediateclassobjectmap.values().forEach(System.out::println);

            //Create Final list
            finalclassobjectmap = temp1.values().stream()
                    .filter(clazz -> !temp2.containsKey(ReflectionUtil.getNameOfObject(clazz)))
                    .collect(Collectors.toMap(o -> ReflectionUtil.getNameOfObject(o), o -> o));
            //append non orphan
            for (Object object : intermediateclassobjectmap.values()) {
                finalclassobjectmap.put(ReflectionUtil.getNameOfObject(object), object);
            }
            final Map<String, Object> temp3 = finalclassobjectmap;              //FINAL CLASSES
//            logger.info("\nClasses: ");
//            finalclassobjectmap.values().forEach(System.out::println);

            /*
            *   LOAD CLASS INSTANCES
             */
            Stream<String> stream3 = Files.lines(Paths.get(ontologypath));
            finalinstanceobjectmap = stream3
                    .filter(line -> !line.startsWith("#") && !line.trim().equalsIgnoreCase("") && ((line.split(",")[0]).trim().equalsIgnoreCase("IoC") || (line.split(",")[0]).trim().equalsIgnoreCase("InstanceOfClass"))) //&& (line.split(",")[2]).trim().equalsIgnoreCase("null")
                    .map(line -> ReflectionUtil.createInstanceOfClazz(ReflectionUtil.getInstanceLabelFromLine(line), temp3.get(ReflectionUtil.getInstanceClassLabelFromLine(line))))
                    .collect(Collectors.toMap(o -> ReflectionUtil.getNameOfObject(o), o -> o));

            final Map<String, Object> temp4 = finalinstanceobjectmap;              //FINAL IOC            

//            logger.info("\nInstances Of Classes: ");
//            finalinstanceobjectmap.values().forEach(System.out::println);

            /*
            *   LOAD OBJECT PROPERTIES
             */
            Stream<String> stream4 = Files.lines(Paths.get(ontologypath));
            initopobjectmap = stream4
                    .filter(line -> !line.startsWith("#") && !line.trim().equalsIgnoreCase("") && ((line.split(",")[0]).trim().equalsIgnoreCase("OP") || (line.split(",")[0]).trim().equalsIgnoreCase("ObjectProperty"))) //&& (line.split(",")[2]).trim().equalsIgnoreCase("null")
                    .map(line -> ReflectionUtil.createOrphanObjectProperty(ReflectionUtil.getOPLabelFromLine(line), temp3.get(ReflectionUtil.getDomainOPLabelFromLine(line)), temp3.get(ReflectionUtil.getRangeOPLabelFromLine(line)), new Boolean(ReflectionUtil.getTransitiveFromLine(line))))
                    .collect(Collectors.toMap(o -> ReflectionUtil.getNameOfObject(o), o -> o));
            final Map<String, Object> temp5 = initopobjectmap;
//            logger.info("Init Pass Of Object Properties: ");
//            initopobjectmap.values().forEach(System.out::println);                        

            Stream<String> stream5 = Files.lines(Paths.get(ontologypath));
            intermediateopobjectmap = stream5
                    .filter(line -> !line.startsWith("#") && !line.trim().equalsIgnoreCase("") && ((line.split(",")[0]).trim().equalsIgnoreCase("OP") || (line.split(",")[0]).trim().equalsIgnoreCase("ObjectProperty")) && !(line.split(",")[5]).trim().equalsIgnoreCase("null"))
                    .map(line -> ReflectionUtil.setParentToObjectPropertyObject(temp5.get(ReflectionUtil.getOPLabelFromLine(line)), temp5.get(ReflectionUtil.getParentalOPLabelFromLine(line))))
                    .collect(Collectors.toMap(o -> ReflectionUtil.getNameOfObject(o), o -> o));
            final Map<String, Object> temp12 = intermediateopobjectmap;
//            logger.info("Intermediate Object Properties: ");
//            intermediateopobjectmap.values().forEach(System.out::println);                

            //Create Final list
            finalopobjectmap = temp5.values().stream()
                    .filter(clazz -> !temp12.containsKey(ReflectionUtil.getNameOfObject(clazz)))
                    .collect(Collectors.toMap(o -> ReflectionUtil.getNameOfObject(o), o -> o));
            //append non orphan
            for (Object object : intermediateopobjectmap.values()) {
                finalopobjectmap.put(ReflectionUtil.getNameOfObject(object), object);
            }
            final Map<String, Object> temp6 = finalopobjectmap;              //FINAL OBJECT PROPERTIES
//            logger.info("\nObject Properties: ");
//            finalopobjectmap.values().forEach(System.out::println);


            /*
            *   LOAD KNOWLEDGE TRIPLES
             */
            Stream<String> stream6 = Files.lines(Paths.get(ontologypath));
            finalktriplesobjectlist = stream6
                    .filter(line -> !line.startsWith("#") && !line.trim().equalsIgnoreCase("") && ((line.split(",")[0]).trim().equalsIgnoreCase("KT") || (line.split(",")[0]).trim().equalsIgnoreCase("KnowledgeTriple"))) //&& (line.split(",")[2]).trim().equalsIgnoreCase("null")
                    .map(line -> ReflectionUtil.createIKnowledgeTriple(
                            temp4.get(  ReflectionUtil.getKTDomainFromLine(line) ),
                            temp6.get(  ReflectionUtil.getKTObjectPropertyFromLine(line) ),
                            temp4.get(  ReflectionUtil.getKTRangeFromLine(line) )
                    ))
                    .collect(Collectors.toList());

            logger.info("\nKnowledge Triples: ");
//            finalktriplesobjectlist.forEach(System.out::println);            
            
            synchronized (ksession) {
                finalclassobjectmap.values().forEach(ksession::insert);
                finalinstanceobjectmap.values().forEach(ksession::insert);
                finalopobjectmap.values().forEach(ksession::insert);
                finalktriplesobjectlist.forEach(ksession::insert);
                
                //fire the rule to check logical consistency of triples
                logger.info("Fire Once in order to get the logical errors");
                
                
                ksession.fireAllRules(new AgendaFilter() {
                    public boolean accept(Match match) {
                        String rulename = match.getRule().getName();
                        if (rulename.startsWith("inference") || rulename.startsWith("debug") || rulename.startsWith("risk") ) {
                            return true;
                        }
                        return false;
                    }
                });
                //handle logical errors
                List<LogicalError> errors = new ArrayList<>();

                for (FactHandle handle : ksession.getFactHandles(new ObjectFilter() {
                    public boolean accept(Object object) {
                        if (LogicalError.class.equals(object.getClass())) {
                            return true;
                        }
                        return false;
                    }
                })) {
                    errors.add((LogicalError) ksession.getFactHandle(handle));
                }

                logger.info("Amount of Logical Errors: " + errors.size());

//                logger.info("Fire 2");
//                FactHandle f1 = (FactHandle) getObjectFromAgenda(ksession, Clazz.class, "Database");
//                Clazz cl1 = (Clazz) ksession.getObject(f1);
//                Clazz cl2 = new Clazz("Relational Database",cl1);
//                
//                logger.info( "fact: "+f1 );
//                logger.info( "fact: "+ksession.getFactCount() );
//
////                ksession.insert(c1);
//                ksession.insert(cl2);
//                ksession.fireAllRules();
//
//                logger.info( "facts: "+ksession.getFactCount() );                
            }//synchronized

        } catch (IOException e) {
            logger.severe("Structural Errors During Ontology Parsing1");
            e.printStackTrace();
        }
        return ksession;
    }//EoM

}//EoC
