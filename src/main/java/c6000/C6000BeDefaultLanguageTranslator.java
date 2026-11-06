// SPDX-License-Identifier: Apache-2.0
package c6000;

/** Migrates C6000:BE:32:default projects from version 1 directly to version 3. */
public class C6000BeDefaultLanguageTranslator extends C6000CompactHalfwordTranslation {
	public C6000BeDefaultLanguageTranslator() {
		super("C6000:BE:32:default", 1, 3);
	}
}
