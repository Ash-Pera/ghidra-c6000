// SPDX-License-Identifier: Apache-2.0
package c6000;

/** Migrates C6000:BE:32:analysis projects from version 1 directly to version 3. */
public class C6000BeAnalysisLanguageTranslator extends C6000CompactHalfwordTranslation {
	public C6000BeAnalysisLanguageTranslator() {
		super("C6000:BE:32:analysis", 1, 3);
	}
}
