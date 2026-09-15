using System.Windows;
using System.Windows.Media;

namespace Sentinel.Gui;

/// <summary>
/// A tiny history graph. Push a normalized 0..1 value each tick and it scrolls right-to-left,
/// drawing a filled area under a stroked line — the live CPU/memory/network strip up top.
/// </summary>
public sealed class Sparkline : FrameworkElement
{
    private readonly double[] _buf = new double[120];
    private int _count;

    public Brush Stroke { get; set; } = Brushes.Teal;
    public Brush Fill { get; set; } = Brushes.Transparent;

    public void Push(double normalized)
    {
        normalized = Math.Clamp(normalized, 0, 1);
        if (_count < _buf.Length)
        {
            _buf[_count++] = normalized;
        }
        else
        {
            Array.Copy(_buf, 1, _buf, 0, _buf.Length - 1);
            _buf[^1] = normalized;
        }
        InvalidateVisual();
    }

    public void Reset()
    {
        _count = 0;
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        if (w <= 0 || h <= 0 || _count < 2) return;

        double step = w / (_buf.Length - 1);
        double x0 = w - (_count - 1) * step; // newest pinned to the right edge

        var area = new StreamGeometry();
        using (var g = area.Open())
        {
            g.BeginFigure(new Point(x0, h), true, true);
            for (int i = 0; i < _count; i++)
                g.LineTo(new Point(x0 + i * step, h - _buf[i] * h), true, false);
            g.LineTo(new Point(x0 + (_count - 1) * step, h), true, false);
        }
        area.Freeze();
        dc.DrawGeometry(Fill, null, area);

        var line = new StreamGeometry();
        using (var g = line.Open())
        {
            g.BeginFigure(new Point(x0, h - _buf[0] * h), false, false);
            for (int i = 1; i < _count; i++)
                g.LineTo(new Point(x0 + i * step, h - _buf[i] * h), true, false);
        }
        line.Freeze();
        var pen = new Pen(Stroke, 1.6);
        pen.Freeze();
        dc.DrawGeometry(null, pen, line);
    }
}
