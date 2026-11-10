package com.cloudtrace.report;

import com.cloudtrace.model.Evidence;
import com.cloudtrace.model.Finding;
import com.cloudtrace.model.Severity;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartUtils;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.plot.PiePlot;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.renderer.category.BarRenderer;
import org.jfree.chart.renderer.xy.XYBarRenderer;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DefaultPieDataset;
import org.jfree.data.time.Hour;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

/** Builds the report charts with JFreeChart and renders them to PNG bytes. */
public final class Charts {
    static final Map<Severity, Color> COLORS = Map.of(
            Severity.CRITICAL, new Color(0xB91C1C), Severity.HIGH, new Color(0xEA580C),
            Severity.MEDIUM, new Color(0xCA8A04), Severity.LOW, new Color(0x2563EB));

    private Charts() {}

    public static JFreeChart activityTimeline(List<Evidence> evidence) {
        TimeSeries all = new TimeSeries("All events");
        TimeSeries failed = new TimeSeries("Failed / denied");
        TimeZone utc = TimeZone.getTimeZone("UTC");
        for (Evidence e : evidence) {
            Hour h = new Hour(Date.from(e.getEventTime()), utc, java.util.Locale.ROOT);
            all.addOrUpdate(h, value(all, h) + 1);
            if (e.isFailure()) failed.addOrUpdate(h, value(failed, h) + 1);
        }
        TimeSeriesCollection ds = new TimeSeriesCollection(utc);
        ds.addSeries(all);
        ds.addSeries(failed);
        JFreeChart chart = ChartFactory.createXYBarChart("Activity per hour (UTC)", "Time", true, "Events",
                ds, PlotOrientation.VERTICAL, true, false, false);
        chart.getXYPlot().setSeriesRenderingOrder(org.jfree.chart.plot.SeriesRenderingOrder.FORWARD);
        XYBarRenderer r = (XYBarRenderer) chart.getXYPlot().getRenderer();
        r.setSeriesPaint(0, new Color(0x64748B));
        r.setSeriesPaint(1, new Color(0xDC2626));
        r.setShadowVisible(false);
        r.setBarPainter(new org.jfree.chart.renderer.xy.StandardXYBarPainter());
        style(chart);
        return chart;
    }

    public static JFreeChart eventsByActor(Map<String, Integer> counts) {
        DefaultCategoryDataset ds = new DefaultCategoryDataset();
        counts.entrySet().stream().limit(10).forEach(e -> ds.addValue(e.getValue(), "Events", e.getKey()));
        JFreeChart chart = ChartFactory.createBarChart("Events by actor (top 10)", "", "Events", ds,
                PlotOrientation.HORIZONTAL, false, false, false);
        CategoryPlot plot = chart.getCategoryPlot();
        BarRenderer r = (BarRenderer) plot.getRenderer();
        r.setSeriesPaint(0, new Color(0x4F46E5));
        r.setShadowVisible(false);
        r.setBarPainter(new org.jfree.chart.renderer.category.StandardBarPainter());
        style(chart);
        return chart;
    }

    public static JFreeChart findingsBySeverity(List<Finding> findings) {
        Map<Severity, Integer> counts = new EnumMap<>(Severity.class);
        for (Finding f : findings) counts.merge(f.severity(), 1, Integer::sum);
        DefaultPieDataset<String> ds = new DefaultPieDataset<>();
        counts.forEach((s, n) -> ds.setValue(s.name(), n));
        JFreeChart chart = ChartFactory.createPieChart("Findings by severity", ds, true, false, false);
        @SuppressWarnings("unchecked")
        PiePlot<String> plot = (PiePlot<String>) chart.getPlot();
        counts.keySet().forEach(s -> plot.setSectionPaint(s.name(), COLORS.get(s)));
        plot.setShadowPaint(null);
        plot.setOutlineVisible(false);
        style(chart);
        return chart;
    }

    public static byte[] png(JFreeChart chart, int width, int height) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ChartUtils.writeChartAsPNG(out, chart, width, height);
        return out.toByteArray();
    }

    private static double value(TimeSeries s, Hour h) {
        Number n = s.getValue(h);
        return n == null ? 0 : n.doubleValue();
    }

    private static void style(JFreeChart chart) {
        chart.setBackgroundPaint(Color.WHITE);
        chart.getPlot().setBackgroundPaint(Color.WHITE);
        chart.getTitle().setFont(new java.awt.Font("SansSerif", java.awt.Font.BOLD, 14));
    }
}
