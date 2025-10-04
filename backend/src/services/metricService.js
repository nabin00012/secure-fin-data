/**
 * Financial Metrics Service
 * वित्तीय मेट्रिक्स सेवा
 * 
 * This service extracts financial data from Excel and PDF files
 * and calculates comprehensive financial metrics including:
 * - Revenue, Expenses, Margins
 * - Growth rates (YoY, CAGR)
 * - Financial ratios
 * - Statistical measures (volatility, moving averages)
 */

const ExcelJS = require('exceljs');
const pdfParse = require('pdf-parse');
const { logger, logFileOperation } = require('../utils/logger');

class MetricService {
    constructor() {
        // Supported file types
        this.supportedTypes = ['.xlsx', '.xls', '.pdf'];

        // Common financial terms for data extraction
        this.financialTerms = {
            revenue: ['revenue', 'sales', 'income', 'turnover', 'receipts'],
            expenses: ['expenses', 'costs', 'expenditure', 'outgoing', 'spending'],
            profit: ['profit', 'earnings', 'net income', 'gain'],
            assets: ['assets', 'holdings', 'investments', 'property'],
            liabilities: ['liabilities', 'debt', 'obligations', 'payables'],
            equity: ['equity', 'capital', 'shareholders equity', 'net worth']
        };

        logger.info('Financial Metrics Service initialized');
    }

    /**
     * Process financial file and extract metrics
     * वित्तीय फाइल को प्रोसेस करें और मेट्रिक्स निकालें
     * 
     * @param {Buffer} fileData - Decrypted file data
     * @param {Object} metadata - File metadata
     * @param {Object} [user] - User information for audit logging
     * @returns {Object} Extracted financial metrics
     */
    async processFinancialFile(fileData, metadata, user = null) {
        try {
            const startTime = Date.now();

            logger.info('Starting financial file processing', {
                fileName: metadata.fileName,
                fileType: metadata.fileType,
                fileSize: fileData.length
            });

            let extractedData;

            // Extract data based on file type
            if (this.isExcelFile(metadata.fileType)) {
                extractedData = await this.extractFromExcel(fileData, metadata);
            } else if (this.isPDFFile(metadata.fileType)) {
                extractedData = await this.extractFromPDF(fileData, metadata);
            } else {
                throw new Error(`Unsupported file type: ${metadata.fileType}`);
            }

            // Calculate comprehensive financial metrics
            const metrics = await this.calculateFinancialMetrics(extractedData);

            const processingTime = Date.now() - startTime;

            // Log file operation for audit
            logFileOperation('PROCESS_METRICS', metadata.fileName, {
                fileSize: fileData.length,
                fileType: metadata.fileType,
                processingTime: processingTime,
                metricsCalculated: Object.keys(metrics).length,
                success: true
            }, user);

            logger.info('Financial file processing completed', {
                fileName: metadata.fileName,
                processingTime: `${processingTime}ms`,
                metricsCount: Object.keys(metrics).length
            });

            return {
                fileMetadata: metadata,
                extractedData: this.sanitizeExtractedData(extractedData),
                metrics: metrics,
                processingInfo: {
                    processingTime: processingTime,
                    timestamp: new Date().toISOString(),
                    version: '1.0'
                }
            };

        } catch (error) {
            logger.error('Financial file processing failed:', error);

            logFileOperation('PROCESS_METRICS_FAILED', metadata.fileName, {
                fileSize: fileData ? fileData.length : 0,
                fileType: metadata.fileType,
                error: error.message,
                success: false
            }, user);

            throw new Error(`Metrics processing failed: ${error.message}`);
        }
    }

    /**
     * Extract financial data from Excel files
     * Excel फाइलों से वित्तीय डेटा निकालें
     * 
     * @param {Buffer} fileData - Excel file data
     * @param {Object} metadata - File metadata
     * @returns {Object} Extracted financial data
     */
    async extractFromExcel(fileData, metadata) {
        try {
            const workbook = new ExcelJS.Workbook();
            await workbook.xlsx.load(fileData);

            const extractedData = {
                sheets: [],
                financialData: {},
                rawData: []
            };

            // Process each worksheet
            workbook.eachSheet((worksheet, sheetId) => {
                logger.debug(`Processing Excel sheet: ${worksheet.name}`, { sheetId });

                const sheetData = {
                    name: worksheet.name,
                    rowCount: worksheet.rowCount,
                    columnCount: worksheet.columnCount,
                    data: []
                };

                // Extract data from each row
                worksheet.eachRow({ includeEmpty: false }, (row, rowNumber) => {
                    const rowData = [];

                    row.eachCell({ includeEmpty: true }, (cell, colNumber) => {
                        let value = cell.value;

                        // Handle different cell types
                        if (cell.type === ExcelJS.ValueType.Number) {
                            value = parseFloat(value);
                        } else if (cell.type === ExcelJS.ValueType.Date) {
                            value = new Date(value).toISOString();
                        } else if (cell.type === ExcelJS.ValueType.Formula) {
                            value = cell.result || cell.formula;
                        } else {
                            value = String(value || '').trim();
                        }

                        rowData.push({
                            column: colNumber,
                            value: value,
                            type: this.detectDataType(value)
                        });
                    });

                    if (rowData.length > 0) {
                        sheetData.data.push({
                            row: rowNumber,
                            cells: rowData
                        });
                    }
                });

                extractedData.sheets.push(sheetData);

                // Extract financial data from this sheet
                const financialData = this.identifyFinancialData(sheetData);
                if (Object.keys(financialData).length > 0) {
                    extractedData.financialData[worksheet.name] = financialData;
                }
            });

            logger.info(`Excel extraction completed`, {
                sheetsProcessed: extractedData.sheets.length,
                financialSheetsFound: Object.keys(extractedData.financialData).length
            });

            return extractedData;

        } catch (error) {
            logger.error('Excel extraction failed:', error);
            throw new Error(`Excel parsing failed: ${error.message}`);
        }
    }

    /**
     * Extract financial data from PDF files
     * PDF फाइलों से वित्तीय डेटा निकालें
     * 
     * @param {Buffer} fileData - PDF file data
     * @param {Object} metadata - File metadata
     * @returns {Object} Extracted financial data
     */
    async extractFromPDF(fileData, metadata) {
        try {
            const pdfData = await pdfParse(fileData);

            const extractedData = {
                text: pdfData.text,
                pages: pdfData.numpages,
                info: pdfData.info,
                financialData: {},
                tables: []
            };

            // Extract tables and financial data from text
            const lines = pdfData.text.split('\n').map(line => line.trim()).filter(line => line);

            // Look for tabular data patterns
            const tables = this.extractTablesFromText(lines);
            extractedData.tables = tables;

            // Extract financial figures from text
            const financialData = this.extractFinancialFromText(lines);
            extractedData.financialData = financialData;

            logger.info(`PDF extraction completed`, {
                pages: pdfData.numpages,
                textLength: pdfData.text.length,
                tablesFound: tables.length,
                financialItemsFound: Object.keys(financialData).length
            });

            return extractedData;

        } catch (error) {
            logger.error('PDF extraction failed:', error);
            throw new Error(`PDF parsing failed: ${error.message}`);
        }
    }

    /**
     * Identify financial data in structured sheet data
     * संरचित शीट डेटा में वित्तीय डेटा की पहचान करें
     * 
     * @param {Object} sheetData - Sheet data from Excel
     * @returns {Object} Identified financial data
     */
    identifyFinancialData(sheetData) {
        const financialData = {};
        const dataMatrix = [];

        // Convert sheet data to matrix for easier processing
        sheetData.data.forEach(rowData => {
            const row = [];
            rowData.cells.forEach(cell => {
                row[cell.column - 1] = cell.value;
            });
            dataMatrix.push(row);
        });

        // Look for financial terms and associated values
        for (let rowIndex = 0; rowIndex < dataMatrix.length; rowIndex++) {
            const row = dataMatrix[rowIndex];

            for (let colIndex = 0; colIndex < row.length; colIndex++) {
                const cellValue = String(row[colIndex] || '').toLowerCase();

                // Check for financial terms
                Object.entries(this.financialTerms).forEach(([category, terms]) => {
                    terms.forEach(term => {
                        if (cellValue.includes(term)) {
                            // Look for numeric values in adjacent cells
                            const values = this.findAdjacentNumbers(dataMatrix, rowIndex, colIndex);

                            if (values.length > 0) {
                                if (!financialData[category]) {
                                    financialData[category] = [];
                                }

                                financialData[category].push({
                                    label: cellValue,
                                    values: values,
                                    position: { row: rowIndex + 1, column: colIndex + 1 }
                                });
                            }
                        }
                    });
                });
            }
        }

        return financialData;
    }

    /**
     * Find adjacent numeric values in a matrix
     * मैट्रिक्स में आसन्न संख्यात्मक मान खोजें
     * 
     * @param {Array} matrix - Data matrix
     * @param {number} row - Current row index
     * @param {number} col - Current column index
     * @returns {Array} Array of numeric values found
     */
    findAdjacentNumbers(matrix, row, col) {
        const numbers = [];

        // Check adjacent cells (right, below, diagonal)
        const checkPositions = [
            [row, col + 1], [row, col + 2], [row, col + 3], // Right
            [row + 1, col], [row + 2, col], // Below
            [row + 1, col + 1] // Diagonal
        ];

        checkPositions.forEach(([r, c]) => {
            if (r < matrix.length && c < (matrix[r] || []).length) {
                const value = matrix[r][c];
                if (typeof value === 'number' && !isNaN(value)) {
                    numbers.push({
                        value: value,
                        position: { row: r + 1, column: c + 1 }
                    });
                } else if (typeof value === 'string') {
                    // Try to parse currency or formatted numbers
                    const parsed = this.parseFormattedNumber(value);
                    if (parsed !== null) {
                        numbers.push({
                            value: parsed,
                            position: { row: r + 1, column: c + 1 },
                            formatted: value
                        });
                    }
                }
            }
        });

        return numbers;
    }

    /**
     * Parse formatted numbers (currency, percentages, etc.)
     * प्रारूपित संख्याओं को पार्स करें (मुद्रा, प्रतिशत, आदि)
     * 
     * @param {string} text - Text to parse
     * @returns {number|null} Parsed number or null
     */
    parseFormattedNumber(text) {
        if (!text || typeof text !== 'string') return null;

        // Remove common currency symbols and formatting
        const cleaned = text
            .replace(/[$₹£€¥,\s]/g, '')
            .replace(/[()]/g, '-') // Negative numbers in parentheses
            .replace(/%$/, ''); // Remove percentage symbol

        const number = parseFloat(cleaned);

        // Check if it's a valid number
        if (!isNaN(number) && isFinite(number)) {
            // Handle percentages
            if (text.includes('%')) {
                return number / 100;
            }
            return number;
        }

        return null;
    }

    /**
     * Extract tables from PDF text lines
     * PDF टेक्स्ट लाइनों से तालिका निकालें
     * 
     * @param {Array} lines - Text lines from PDF
     * @returns {Array} Extracted tables
     */
    extractTablesFromText(lines) {
        const tables = [];
        let currentTable = null;

        lines.forEach((line, index) => {
            // Look for tabular patterns (multiple numbers with separators)
            const numbers = (line.match(/[\d,.$₹£€¥%-]+/g) || []);
            const hasMultipleNumbers = numbers.length >= 2;

            // Look for table headers or financial statement indicators
            const looksLikeHeader = /^(.*)(revenue|income|expenses|profit|assets|liabilities|cash|balance)/i.test(line);

            if (looksLikeHeader || hasMultipleNumbers) {
                if (!currentTable) {
                    currentTable = {
                        startLine: index,
                        rows: [],
                        type: looksLikeHeader ? 'financial-statement' : 'data-table'
                    };
                }

                currentTable.rows.push({
                    lineNumber: index + 1,
                    text: line,
                    numbers: numbers.map(num => this.parseFormattedNumber(num)).filter(n => n !== null)
                });

            } else if (currentTable && currentTable.rows.length > 0) {
                // End current table if we hit non-tabular content
                currentTable.endLine = index - 1;
                tables.push(currentTable);
                currentTable = null;
            }
        });

        // Add the last table if exists
        if (currentTable) {
            currentTable.endLine = lines.length - 1;
            tables.push(currentTable);
        }

        return tables;
    }

    /**
     * Extract financial data from text lines
     * टेक्स्ट लाइनों से वित्तीय डेटा निकालें
     * 
     * @param {Array} lines - Text lines from PDF
     * @returns {Object} Extracted financial data
     */
    extractFinancialFromText(lines) {
        const financialData = {};

        lines.forEach((line, index) => {
            const lowerLine = line.toLowerCase();

            // Look for financial terms with associated numbers
            Object.entries(this.financialTerms).forEach(([category, terms]) => {
                terms.forEach(term => {
                    if (lowerLine.includes(term)) {
                        // Extract numbers from the same line or nearby lines
                        const numbers = this.extractNumbersFromLine(line);

                        if (numbers.length === 0) {
                            // Check next few lines for numbers
                            for (let i = 1; i <= 3 && index + i < lines.length; i++) {
                                const nextLineNumbers = this.extractNumbersFromLine(lines[index + i]);
                                if (nextLineNumbers.length > 0) {
                                    numbers.push(...nextLineNumbers);
                                    break;
                                }
                            }
                        }

                        if (numbers.length > 0) {
                            if (!financialData[category]) {
                                financialData[category] = [];
                            }

                            financialData[category].push({
                                label: line.trim(),
                                values: numbers,
                                lineNumber: index + 1
                            });
                        }
                    }
                });
            });
        });

        return financialData;
    }

    /**
     * Extract numbers from a text line
     * टेक्स्ट लाइन से संख्या निकालें
     * 
     * @param {string} line - Text line
     * @returns {Array} Array of extracted numbers
     */
    extractNumbersFromLine(line) {
        const numbers = [];
        const numberMatches = line.match(/[\d,.$₹£€¥%-]+/g) || [];

        numberMatches.forEach(match => {
            const parsed = this.parseFormattedNumber(match);
            if (parsed !== null) {
                numbers.push({
                    value: parsed,
                    formatted: match
                });
            }
        });

        return numbers;
    }

    /**
     * Calculate comprehensive financial metrics
     * व्यापक वित्तीय मेट्रिक्स की गणना करें
     * 
     * @param {Object} extractedData - Extracted financial data
     * @returns {Object} Calculated financial metrics
     */
    async calculateFinancialMetrics(extractedData) {
        const metrics = {
            basicMetrics: {},
            ratios: {},
            growthMetrics: {},
            statisticalMetrics: {},
            summary: {}
        };

        try {
            // Extract key financial figures
            const figures = this.consolidateFinancialFigures(extractedData);

            // Calculate basic metrics
            metrics.basicMetrics = this.calculateBasicMetrics(figures);

            // Calculate financial ratios
            metrics.ratios = this.calculateFinancialRatios(figures);

            // Calculate growth metrics
            metrics.growthMetrics = this.calculateGrowthMetrics(figures);

            // Calculate statistical metrics
            metrics.statisticalMetrics = this.calculateStatisticalMetrics(figures);

            // Generate summary
            metrics.summary = this.generateMetricsSummary(metrics);

            logger.info('Financial metrics calculation completed', {
                basicMetrics: Object.keys(metrics.basicMetrics).length,
                ratios: Object.keys(metrics.ratios).length,
                growthMetrics: Object.keys(metrics.growthMetrics).length
            });

        } catch (error) {
            logger.error('Financial metrics calculation failed:', error);
            throw new Error(`Metrics calculation failed: ${error.message}`);
        }

        return metrics;
    }

    /**
     * Consolidate financial figures from extracted data
     * निकाले गए डेटा से वित्तीय आंकड़े समेकित करें
     * 
     * @param {Object} extractedData - Extracted financial data
     * @returns {Object} Consolidated financial figures
     */
    consolidateFinancialFigures(extractedData) {
        const figures = {
            revenue: [],
            expenses: [],
            profit: [],
            assets: [],
            liabilities: [],
            equity: [],
            dates: []
        };

        // Process data from all sheets or sections
        if (extractedData.financialData) {
            Object.values(extractedData.financialData).forEach(sectionData => {
                Object.entries(sectionData).forEach(([category, items]) => {
                    if (figures[category]) {
                        items.forEach(item => {
                            item.values.forEach(valueData => {
                                figures[category].push(valueData.value);
                            });
                        });
                    }
                });
            });
        }

        // Remove duplicates and sort
        Object.keys(figures).forEach(key => {
            figures[key] = [...new Set(figures[key])].sort((a, b) => b - a);
        });

        return figures;
    }

    /**
     * Calculate basic financial metrics
     * बुनियादी वित्तीय मेट्रिक्स की गणना करें
     * 
     * @param {Object} figures - Consolidated financial figures
     * @returns {Object} Basic financial metrics
     */
    calculateBasicMetrics(figures) {
        const metrics = {};

        // Revenue metrics
        if (figures.revenue.length > 0) {
            metrics.totalRevenue = figures.revenue.reduce((sum, val) => sum + val, 0);
            metrics.averageRevenue = metrics.totalRevenue / figures.revenue.length;
            metrics.maxRevenue = Math.max(...figures.revenue);
            metrics.minRevenue = Math.min(...figures.revenue);
        }

        // Expense metrics
        if (figures.expenses.length > 0) {
            metrics.totalExpenses = figures.expenses.reduce((sum, val) => sum + val, 0);
            metrics.averageExpenses = metrics.totalExpenses / figures.expenses.length;
            metrics.maxExpenses = Math.max(...figures.expenses);
            metrics.minExpenses = Math.min(...figures.expenses);
        }

        // Margin calculations
        if (metrics.totalRevenue && metrics.totalExpenses) {
            metrics.grossMargin = metrics.totalRevenue - metrics.totalExpenses;
            metrics.grossMarginPercentage = (metrics.grossMargin / metrics.totalRevenue) * 100;

            // Net margin (assuming profit data includes net profit)
            if (figures.profit.length > 0) {
                metrics.netProfit = figures.profit.reduce((sum, val) => sum + val, 0);
                metrics.netMarginPercentage = (metrics.netProfit / metrics.totalRevenue) * 100;
            }
        }

        return metrics;
    }

    /**
     * Calculate financial ratios
     * वित्तीय अनुपात की गणना करें
     * 
     * @param {Object} figures - Consolidated financial figures
     * @returns {Object} Financial ratios
     */
    calculateFinancialRatios(figures) {
        const ratios = {};

        // Current Ratio (if we have current assets and liabilities)
        if (figures.assets.length > 0 && figures.liabilities.length > 0) {
            const totalAssets = figures.assets.reduce((sum, val) => sum + val, 0);
            const totalLiabilities = figures.liabilities.reduce((sum, val) => sum + val, 0);

            if (totalLiabilities > 0) {
                ratios.currentRatio = totalAssets / totalLiabilities;
                ratios.debtToEquityRatio = totalLiabilities / (totalAssets - totalLiabilities);
            }

            ratios.assetTurnover = figures.revenue.length > 0 ?
                figures.revenue.reduce((sum, val) => sum + val, 0) / totalAssets : 0;
        }

        // Debt-to-Equity Ratio
        if (figures.liabilities.length > 0 && figures.equity.length > 0) {
            const totalDebt = figures.liabilities.reduce((sum, val) => sum + val, 0);
            const totalEquity = figures.equity.reduce((sum, val) => sum + val, 0);

            if (totalEquity > 0) {
                ratios.debtToEquityRatio = totalDebt / totalEquity;
            }
        }

        // Return on Assets (ROA)
        if (figures.profit.length > 0 && figures.assets.length > 0) {
            const netIncome = figures.profit.reduce((sum, val) => sum + val, 0);
            const totalAssets = figures.assets.reduce((sum, val) => sum + val, 0);

            if (totalAssets > 0) {
                ratios.returnOnAssets = (netIncome / totalAssets) * 100;
            }
        }

        return ratios;
    }

    /**
     * Calculate growth metrics (YoY, CAGR)
     * वृद्धि मेट्रिक्स (YoY, CAGR) की गणना करें
     * 
     * @param {Object} figures - Consolidated financial figures
     * @returns {Object} Growth metrics
     */
    calculateGrowthMetrics(figures) {
        const growth = {};

        // YoY Growth for Revenue
        if (figures.revenue.length >= 2) {
            const sortedRevenue = [...figures.revenue].sort();
            const oldestRevenue = sortedRevenue[0];
            const newestRevenue = sortedRevenue[sortedRevenue.length - 1];

            if (oldestRevenue > 0) {
                growth.revenueYoYGrowth = ((newestRevenue - oldestRevenue) / oldestRevenue) * 100;
            }

            // CAGR calculation (assuming data spans multiple years)
            const years = Math.max(2, figures.revenue.length);
            growth.revenuCAGR = (Math.pow(newestRevenue / oldestRevenue, 1 / (years - 1)) - 1) * 100;
        }

        // YoY Growth for Profit
        if (figures.profit.length >= 2) {
            const sortedProfit = [...figures.profit].sort();
            const oldestProfit = sortedProfit[0];
            const newestProfit = sortedProfit[sortedProfit.length - 1];

            if (oldestProfit > 0) {
                growth.profitYoYGrowth = ((newestProfit - oldestProfit) / oldestProfit) * 100;
            }
        }

        return growth;
    }

    /**
     * Calculate statistical metrics
     * सांख्यिकीय मेट्रिक्स की गणना करें
     * 
     * @param {Object} figures - Consolidated financial figures
     * @returns {Object} Statistical metrics
     */
    calculateStatisticalMetrics(figures) {
        const stats = {};

        // Revenue statistics
        if (figures.revenue.length > 0) {
            stats.revenueStats = this.calculateArrayStatistics(figures.revenue);
        }

        // Profit statistics
        if (figures.profit.length > 0) {
            stats.profitStats = this.calculateArrayStatistics(figures.profit);
        }

        // Moving averages (if we have time series data)
        if (figures.revenue.length >= 3) {
            stats.revenueMovingAverage = this.calculateMovingAverage(figures.revenue, 3);
        }

        return stats;
    }

    /**
     * Calculate statistical measures for an array of numbers
     * संख्याओं की श्रृंखला के लिए सांख्यिकीय माप की गणना करें
     * 
     * @param {Array} values - Array of numbers
     * @returns {Object} Statistical measures
     */
    calculateArrayStatistics(values) {
        if (!values || values.length === 0) return {};

        const sorted = [...values].sort((a, b) => a - b);
        const mean = values.reduce((sum, val) => sum + val, 0) / values.length;

        // Variance and Standard Deviation
        const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
        const standardDeviation = Math.sqrt(variance);

        return {
            mean: mean,
            median: sorted[Math.floor(sorted.length / 2)],
            standardDeviation: standardDeviation,
            variance: variance,
            min: sorted[0],
            max: sorted[sorted.length - 1],
            range: sorted[sorted.length - 1] - sorted[0],
            coefficientOfVariation: mean !== 0 ? (standardDeviation / mean) * 100 : 0
        };
    }

    /**
     * Calculate moving average
     * मूविंग एवरेज की गणना करें
     * 
     * @param {Array} values - Array of numbers
     * @param {number} window - Moving average window size
     * @returns {Array} Moving averages
     */
    calculateMovingAverage(values, window) {
        const movingAverages = [];

        for (let i = window - 1; i < values.length; i++) {
            const windowValues = values.slice(i - window + 1, i + 1);
            const average = windowValues.reduce((sum, val) => sum + val, 0) / window;
            movingAverages.push(average);
        }

        return movingAverages;
    }

    /**
     * Generate metrics summary
     * मेट्रिक्स सारांश जेनरेट करें
     * 
     * @param {Object} metrics - All calculated metrics
     * @returns {Object} Metrics summary
     */
    generateMetricsSummary(metrics) {
        const summary = {
            totalMetricsCalculated: 0,
            keyInsights: [],
            riskIndicators: [],
            recommendations: []
        };

        // Count total metrics
        Object.values(metrics).forEach(category => {
            if (typeof category === 'object') {
                summary.totalMetricsCalculated += Object.keys(category).length;
            }
        });

        // Generate insights based on calculated metrics
        if (metrics.basicMetrics.grossMarginPercentage) {
            if (metrics.basicMetrics.grossMarginPercentage > 50) {
                summary.keyInsights.push('Strong gross margin indicates good pricing power');
            } else if (metrics.basicMetrics.grossMarginPercentage < 20) {
                summary.riskIndicators.push('Low gross margin may indicate pricing pressure');
            }
        }

        if (metrics.ratios.currentRatio) {
            if (metrics.ratios.currentRatio < 1) {
                summary.riskIndicators.push('Current ratio below 1 indicates liquidity concerns');
            } else if (metrics.ratios.currentRatio > 2) {
                summary.keyInsights.push('Strong current ratio indicates good liquidity');
            }
        }

        if (metrics.growthMetrics.revenueYoYGrowth) {
            if (metrics.growthMetrics.revenueYoYGrowth > 20) {
                summary.keyInsights.push('Strong revenue growth indicates business expansion');
            } else if (metrics.growthMetrics.revenueYoYGrowth < 0) {
                summary.riskIndicators.push('Negative revenue growth indicates declining business');
            }
        }

        return summary;
    }

    /**
     * Sanitize extracted data for secure storage
     * सुरक्षित भंडारण के लिए निकाले गए डेटा को साफ़ करें
     * 
     * @param {Object} extractedData - Raw extracted data
     * @returns {Object} Sanitized data
     */
    sanitizeExtractedData(extractedData) {
        // Remove or limit large text fields to prevent storage bloat
        const sanitized = { ...extractedData };

        if (sanitized.text && sanitized.text.length > 10000) {
            sanitized.text = sanitized.text.substring(0, 10000) + '... [TRUNCATED]';
        }

        // Remove raw sheet data but keep summarized financial data
        if (sanitized.sheets) {
            sanitized.sheets = sanitized.sheets.map(sheet => ({
                name: sheet.name,
                rowCount: sheet.rowCount,
                columnCount: sheet.columnCount,
                hasFinancialData: sheet.data && sheet.data.length > 0
            }));
        }

        return sanitized;
    }

    /**
     * Detect data type of a cell value
     * सेल मान के डेटा प्रकार का पता लगाएं
     * 
     * @param {any} value - Cell value
     * @returns {string} Data type
     */
    detectDataType(value) {
        if (typeof value === 'number') {
            return 'number';
        } else if (value instanceof Date || (typeof value === 'string' && !isNaN(Date.parse(value)))) {
            return 'date';
        } else if (typeof value === 'string' && /^[\d,.$₹£€¥%-]+$/.test(value)) {
            return 'currency';
        } else if (typeof value === 'string' && /%$/.test(value)) {
            return 'percentage';
        } else {
            return 'text';
        }
    }

    /**
     * Check if file is Excel type
     * जांचें कि फाइल Excel प्रकार की है या नहीं
     * 
     * @param {string} fileType - File type/extension
     * @returns {boolean} True if Excel file
     */
    isExcelFile(fileType) {
        return ['.xlsx', '.xls'].includes(fileType?.toLowerCase());
    }

    /**
     * Check if file is PDF type
     * जांचें कि फाइल PDF प्रकार की है या नहीं
     * 
     * @param {string} fileType - File type/extension
     * @returns {boolean} True if PDF file
     */
    isPDFFile(fileType) {
        return fileType?.toLowerCase() === '.pdf';
    }

    /**
     * Get service health status
     * सेवा स्वास्थ्य स्थिति प्राप्त करें
     */
    getHealthStatus() {
        return {
            status: 'healthy',
            supportedTypes: this.supportedTypes,
            financialTermsConfigured: Object.keys(this.financialTerms).length,
            lastHealthCheck: new Date().toISOString()
        };
    }
}

module.exports = MetricService;