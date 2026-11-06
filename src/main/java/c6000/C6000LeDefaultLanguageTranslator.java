/* ### */
package c6000;

/** Migrates C6000:LE:32:default projects from language version 1 to 2. */
public class C6000LeDefaultLanguageTranslator extends C6000CompactHalfwordTranslation {
	public C6000LeDefaultLanguageTranslator() {
		super("C6000:LE:32:default", 1, 2);
	}
}
