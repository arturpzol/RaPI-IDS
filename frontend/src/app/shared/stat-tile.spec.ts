import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { StatTile } from './stat-tile';

/** The three shapes a tile takes, side by side in one row, the way a screen
 *  shows them. Measured rather than inspected: the fault this exists for was a
 *  tile 100px narrower than its neighbours, which no assertion about classes or
 *  attributes could have seen. */
@Component({
  imports: [StatTile],
  template: `
    <div class="tiles" style="display:grid;grid-template-columns:repeat(3,1fr);
                              gap:0.85rem;width:900px">
      <stat-tile label="Plain" value="1" hint="a hint" />
      <stat-tile label="Linked" value="2" hint="a hint" [link]="['/ids']" />
      <stat-tile label="Acting" value="3" hint="a hint" [acts]="true" />
      <stat-tile label="Rated" value="4" hint="a hint" tone="rating sev-1 lit" />
      <stat-tile label="Quiet" value="-" hint="a hint" tone="rating sev-1" />
      <stat-tile label="Noise" value="9" hint="a hint" tone="rating sev-4 lit" />
      <stat-tile label="Silent" value="-" hint="a hint" tone="rating sev-4" />
    </div>`,
})
class Row {}

describe('StatTile', () => {
  let fixture: ComponentFixture<Row>;

  function boxes() {
    const tiles = Array.from(
      (fixture.nativeElement as HTMLElement).querySelectorAll<HTMLElement>('.tile'));
    return tiles.map((t) => ({
      tag: t.tagName,
      width: Math.round(t.getBoundingClientRect().width),
      height: Math.round(t.getBoundingClientRect().height),
      align: getComputedStyle(t).textAlign,
      font: getComputedStyle(t.querySelector('.tile-label')!).fontFamily,
    }));
  }

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideRouter([])] });
    fixture = TestBed.createComponent(Row);
    document.body.appendChild(fixture.nativeElement);   // laid out, not detached
    fixture.detectChanges();
  });

  afterEach(() => fixture?.destroy());

  it('gives every tile in a row the same box', () => {
    // A button carries the browser's own stylesheet: it shrinks to its content
    // instead of filling the host. Inside a stat-tile that came out 189px wide
    // against the 291 of its neighbours, and the row had a hole in it.
    const [plain, linked, acting] = boxes();
    expect(acting.tag).toBe('BUTTON');
    expect(acting.width).toBe(plain.width);
    expect(acting.width).toBe(linked.width);
    expect(acting.height).toBe(plain.height);
  });

  it('gives every tile in a row the same type', () => {
    // The other half of the same stylesheet: centred text and Arial.
    const [plain, , acting] = boxes();
    expect(acting.align).toBe(plain.align);
    expect(acting.font).toBe(plain.font);
  });

  it('keeps its own classes when a rating adds one', () => {
    // The tone arrives as a [class] binding beside a static class attribute.
    // If those did not merge, the tile would lose its border, its padding and
    // its whole box, which is the sort of thing a class assertion catches and
    // a measurement does not: a tile with no styling still has a width.
    const rated = (fixture.nativeElement as HTMLElement)
      .querySelectorAll<HTMLElement>('.tile')[3];
    expect(rated.classList.contains('tile')).toBeTrue();
    expect(rated.classList.contains('rating')).toBeTrue();
    expect(rated.classList.contains('sev-1')).toBeTrue();
    expect(rated.classList.contains('lit')).toBeTrue();
  });

  it('measures a rating tile the same as the rest of the row', () => {
    // Same fault as the button, one variant later: a tile with an extra class
    // has to keep the box its neighbours have.
    const [plain, , , rated] = boxes();
    expect(rated.width).toBe(plain.width);
    expect(rated.height).toBe(plain.height);
  });

  it('colours the number only where the rating has something in it', () => {
    // Colour is the message on these tiles. A row tinted whatever the counts
    // says nothing at all, and the dash on an empty tier has to read as quiet
    // rather than as a reading.
    const tiles = (fixture.nativeElement as HTMLElement)
      .querySelectorAll<HTMLElement>('.tile');
    const colour = (t: HTMLElement) =>
      getComputedStyle(t.querySelector('.tile-value')!).color;
    // The top tier carries its own colour when it is not empty.
    expect(colour(tiles[3])).not.toBe(colour(tiles[4]));
    // And the quiet tiers, which have no colour of their own, still have to
    // tell a count from a dash. Without this the dim rule can be dropped and
    // only the two loud tiers notice.
    expect(colour(tiles[5])).not.toBe(colour(tiles[6]));
  });

  it('is a link when it leads somewhere else and a button when it acts', () => {
    const [plain, linked, acting] = boxes();
    expect(plain.tag).toBe('DIV');
    expect(linked.tag).toBe('A');
    expect(acting.tag).toBe('BUTTON');
  });
});
